#region Usings

using System;
using System.Linq;
using System.Web;
using DotNetNuke.Entities.Users;        //for UserController
using DotNetNuke.Instrumentation;       //for logger
using DotNetNuke.Services.Log.EventLog; //for eventlog
using DotNetNuke.Services.Authentication;   //for AuthenticationLoginBase
using DotNetNuke.Security.Membership;   //for UserLoginStatus
using System.Security.Claims;           //for ClaimsPrincipal
using System.IdentityModel.Services; //SignInRequestMessage
using System.IdentityModel.Tokens; //SecurityTokenHandlerCollection

using Globals = DotNetNuke.Common.Globals;
using System.Xml;
using System.IO;
using DotNetNuke.Security.Roles;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;


#endregion

namespace DNN.Authentication.SAML
{

	public partial class Login : AuthenticationLoginBase
    {
		private static readonly ILog Logger = LoggerSource.Instance.GetLogger(typeof (Login));
        private static readonly IEventLogController eventLog = new EventLogController();
        private static DotNetNuke.Entities.Portals.PortalSettings staticPortalSettings;
        private static DNNAuthenticationSAMLAuthenticationConfig config;


        public static void LogToEventLog(string methodName, string message)
        {
            eventLog.AddLog("DNN.Authentication.SAML." + methodName + " : " + DateTime.Now.ToString("MM/dd/yyyy hh:mm:ss:fff"), message, staticPortalSettings, -1, EventLogController.EventLogType.ADMIN_ALERT);
        }

        public override bool Enabled
		{
			get
			{
                return AuthenticationConfig.GetConfig(PortalId).Enabled;
			}
		}

		protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            staticPortalSettings = PortalSettings;
            string redirectTo = "~/";

            try
            {
                config = DNNAuthenticationSAMLAuthenticationConfig.GetConfig(PortalId);
                if (Request.HttpMethod == "POST" && !Request.IsAuthenticated)
                {
                    if (Request.Form["RelayState"] != null)
                    {
                        string relayState = HttpUtility.UrlDecode(Request.Form["RelayState"]);
                        LogToEventLog("DNN.Authentication.SAML.OnLoad(post !auth)", string.Format("relayState : {0}", relayState));
                        var relayStateSplit = relayState.Split(new char[] { '&' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (string s in relayStateSplit)
                        {
                            if (s.ToLower().StartsWith("returnurl"))
                            {
                                redirectTo = "~" + s.Replace("returnurl=", "");
                                break;
                            }
                        }
                    }


                    X509Certificate2 myCert = StaticHelper.GetCert(config.OurCertFriendlyName);
                    System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
                    string responseXML = enc.GetString(Convert.FromBase64String(Request.Form["SAMLResponse"]));
                    ResponseHandler responseHandler = new ResponseHandler(responseXML, myCert,
                            config.TheirCert
                        );

                    LogToEventLog("DNN.Authentication.SAML.OnLoad(post !auth)", "responseXML : " + responseHandler.ResponseString());


                    string emailFromSAMLResponse = responseHandler.GetNameID();
                    UserInfo userInfo = UserController.GetUserByName(PortalSettings.PortalId, emailFromSAMLResponse);
                    if (userInfo == null)
                    {
                        userInfo = new UserInfo();
                        userInfo.Username = emailFromSAMLResponse;
                        userInfo.PortalID = base.PortalId;
                        userInfo.DisplayName = emailFromSAMLResponse;
                        userInfo.Email = emailFromSAMLResponse;
                        userInfo.FirstName = emailFromSAMLResponse;
                        userInfo.LastName = emailFromSAMLResponse;
                        userInfo.Membership.Password = UserController.GeneratePassword(12).ToString();

                        UserCreateStatus rc = UserController.CreateUser(ref userInfo);
                        if (rc == UserCreateStatus.Success)
                            addRoleToUser(userInfo, "Subscribers", DateTime.MaxValue);
                    }
                    else
                    {
                        LogToEventLog("DNN.Authentication.SAML.OnLoad(post !auth)", String.Format("FoundUser userInfo.Username: {0}", userInfo.Username));
                    }


                    string sessionIndexFromSAMLResponse = responseHandler.GetSessionIndex();
                    Session["sessionIndexFromSAMLResponse"] = sessionIndexFromSAMLResponse;


                    UserValidStatus validStatus = UserController.ValidateUser(userInfo, PortalId, true);
                    UserLoginStatus loginStatus = validStatus == UserValidStatus.VALID ? UserLoginStatus.LOGIN_SUCCESS : UserLoginStatus.LOGIN_FAILURE;
                    if (loginStatus == UserLoginStatus.LOGIN_SUCCESS)
                    {
                        //Raise UserAuthenticated Event
                        var eventArgs = new UserAuthenticatedEventArgs(userInfo, userInfo.Email, loginStatus, config.DNNAuthName) //"DNN" is default, "SAML" is this one.  How did it get named SAML????
                        {
                            Authenticated = true,
                            Message = "User authorized",
                            RememberMe = false
                        };
                        OnUserAuthenticated(eventArgs);
                    }
                }
                else if (Request.IsAuthenticated)
                {
                    //if (!Response.IsRequestBeingRedirected)
                    //    Response.Redirect(Page.ResolveUrl("~/"), false);
                }
                else
                {
                    XmlDocument request = GenerateSAMLRequest();
                    X509Certificate2 cert = StaticHelper.GetCert(config.OurCertFriendlyName);
                    request = StaticHelper.SignSAMLRequest(request, cert);
                    LogToEventLog("DNN.Authentication.SAML.OnLoad()", string.Format("request xml {0}", request.OuterXml));
                    String convertedRequestXML = StaticHelper.Base64CompressUrlEncode(request);
                    redirectTo = 
                        config.IdPURL + 
                        (config.IdPURL.Contains("?") ? "&" : "?") +
                        "SAMLRequest=" + convertedRequestXML;
                    if (Request.QueryString.Count > 0)
                        redirectTo += "&RelayState=" + HttpUtility.UrlEncode(Request.Url.Query.Replace("?", "&"));
                }
            }
            catch (System.Threading.ThreadAbortException tae)
            {
                LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", string.Format("Redirecting to  {0}", redirectTo));
                Response.Redirect(Page.ResolveUrl(redirectTo), false); 
            }
            catch (Exception ex)
            {
                LogToEventLog("DNN.Authentication.SAML.OnLoad()", string.Format("Exception  {0}", ex.Message));
                redirectTo = "~/";
            }

            Response.Redirect(Page.ResolveUrl(redirectTo), false);
        }

        private XmlDocument GenerateSAMLRequest()
        {
            DateTime now = DateTime.SpecifyKind(DateTime.Now, DateTimeKind.Utc);
            string authnRequestID = "_" + Guid.NewGuid().ToString().Replace("-", "");

            string requestXML = @"<samlp:AuthnRequest " +
                @" ID=""" + authnRequestID + @"""" +
                @" IssueInstant = """ + now.ToString("O") + @"""" +    
                @" Version = ""2.0"" " + 
                @" Destination = """ + config.IdPURL + @""""  + 
                @" ForceAuthn = ""false"" " + 
                @" IsPassive = ""false"" " + 
                @" ProtocolBinding = ""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" " + 
                @" AssertionConsumerServiceURL = """ + config.ConsumerServURL + @"""" + 
                @" xmlns:samlp = ""urn:oasis:names:tc:SAML:2.0:protocol"">" +
                @" <saml:Issuer xmlns:saml = ""urn:oasis:names:tc:SAML:2.0:assertion"">" + config.OurIssuerEntityID + @"</saml:Issuer>" +
                @" </samlp:AuthnRequest>";

            XmlDocument xml = new XmlDocument();
            xml.LoadXml(requestXML);
            return xml;
        }

        public bool addRoleToUser(UserInfo user, string roleName, DateTime expiry)
        {
            bool rc = false;
            var roleCtl = new RoleController();
            RoleInfo newRole = roleCtl.GetRoleByName(user.PortalID, roleName);
            if (newRole != null && user != null)
            {
                rc = user.IsInRole(roleName);
                roleCtl.AddUserRole(user.PortalID, user.UserID, newRole.RoleID, DateTime.MinValue, expiry);
                // Refresh user and check if role was added
                user = UserController.GetUserById(user.PortalID, user.UserID);
                rc = user.IsInRole(roleName);
            }
            return rc;
        }



        private void PrintOutKeyValues(string name, System.Collections.Specialized.NameValueCollection coll)
        {
            if (coll == null)
                LogToEventLog("DNN.Authentication.SAML.PrintOutKeyValues()", string.Format("{0} is null", name));
            else
            {
                LogToEventLog("DNN.Authentication.SAML.PrintOutKeyValues()", string.Format("{0} has {1} elements", name, coll.Count));

                foreach (string key in coll.AllKeys)
                    LogToEventLog("DNN.Authentication.SAML.PrintOutKeyValues(post !auth)", string.Format("{0} [{1}] = [{2}]", name, key, coll[key]));
            }

        }
    }
}



