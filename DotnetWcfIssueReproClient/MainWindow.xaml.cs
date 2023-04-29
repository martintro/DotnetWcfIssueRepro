using ServiceReference;
using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security.Tokens;
using System.Windows;
using System.Xml;

namespace DotnetWcfIssueReproClient
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            var factory = new ChannelFactory<IService>(CreateBinding(), new EndpointAddress("net.tcp://localhost:8741/Design_Time_Addresses/DotnetWcfIssueReproService/"));
            var channel = factory.CreateChannelWithIssuedToken(CreateToken());

            // DOES NOT WORK, JUST HANGS
            var response = channel.GetData(1);
            // WORKS WITHOUT HANGING
            //var response = channel.GetDataAsync(1).GetAwaiter().GetResult();

            MessageBox.Show(response);
        }

        private XmlElement CreateTokenReference()
        {
            var doc = new XmlDocument();
            var tokenReference = doc.CreateElement("wsse", "SecurityTokenReference", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            var attr = doc.CreateAttribute("a", "TokenType", "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd");
            attr.Value = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
            tokenReference.Attributes.Append(attr);
            var keyId = doc.CreateElement("wsse", "KeyIdentifier", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            attr = doc.CreateAttribute("ValueType");
            attr.Value = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID";
            keyId.Attributes.Append(attr);
            keyId.InnerText = "_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75";
            tokenReference.AppendChild(keyId);
            return tokenReference;
        }

        private GenericXmlSecurityToken CreateToken()
        {
            var doc = new XmlDocument();
            doc.LoadXml("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ID=\"_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\" Version=\"2.0\" IssueInstant=\"2014-07-17T01:01:48Z\">" +
                        "<saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>" +
                        "<saml:Subject>" +
                        "<saml:NameID SPNameQualifier=\"http://sp.example.com/demo1/metadata.php\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>" +
                        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" +
                        "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-01-18T06:21:48Z\" Recipient=\"http://sp.example.com/demo1/index.php?acs\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\"/>" +
                        "</saml:SubjectConfirmation>" +
                        "</saml:Subject>" +
                        "<saml:Conditions NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2024-01-18T06:21:48Z\">" +
                        "<saml:AudienceRestriction>" +
                        "<saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>" +
                        "</saml:AudienceRestriction>" +
                        "</saml:Conditions>" +
                        "<saml:AuthnStatement AuthnInstant=\"2014-07-17T01:01:48Z\" SessionNotOnOrAfter=\"2024-07-17T09:01:48Z\" SessionIndex=\"_be9967abd904ddcae3c0eb4189adbe3f71e327cf93\">" +
                        "<saml:AuthnContext>" +
                        "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>" +
                        "</saml:AuthnContext>" +
                        "</saml:AuthnStatement>" +
                        "<saml:AttributeStatement>" +
                        "<saml:Attribute Name=\"uid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">" +
                        "<saml:AttributeValue xsi:type=\"xs:string\">test</saml:AttributeValue>" +
                        "</saml:Attribute>" +
                        "<saml:Attribute Name=\"mail\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">" +
                        "<saml:AttributeValue xsi:type=\"xs:string\">test@example.com</saml:AttributeValue>" +
                        "</saml:Attribute>" +
                        "<saml:Attribute Name=\"eduPersonAffiliation\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">" +
                        "<saml:AttributeValue xsi:type=\"xs:string\">users</saml:AttributeValue>" +
                        "<saml:AttributeValue xsi:type=\"xs:string\">examplerole1</saml:AttributeValue>" +
                        "</saml:Attribute>" +
                        "</saml:AttributeStatement>" +
                        "</saml:Assertion>");
            
            var proofToken = new BinarySecretSecurityToken(Convert.FromBase64String("PJC7HnliwcxXw4FM8Ep3sX9NIL3R5CZnDvp8IyyCSlg="));
            return new GenericXmlSecurityToken(doc.DocumentElement, proofToken, DateTime.UtcNow, DateTime.MaxValue,
                new GenericXmlSecurityKeyIdentifierClause(CreateTokenReference()), new GenericXmlSecurityKeyIdentifierClause(CreateTokenReference()), null);
        }

        private Binding CreateBinding()
        {
            var netTcpSecureConversationBinding = new CustomBinding();
            var issuedTokenOverTransportBindingElement = SecurityBindingElement.CreateSecureConversationBindingElement(
                SecurityBindingElement.CreateIssuedTokenOverTransportBindingElement(new IssuedSecurityTokenParameters()));
            issuedTokenOverTransportBindingElement.MessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            netTcpSecureConversationBinding.Elements.Add(issuedTokenOverTransportBindingElement);
            netTcpSecureConversationBinding.Elements.Add(new BinaryMessageEncodingBindingElement
            {
                ReaderQuotas = XmlDictionaryReaderQuotas.Max
            });
            netTcpSecureConversationBinding.Elements.Add(new SslStreamSecurityBindingElement
            {
                RequireClientCertificate = false
            });
            netTcpSecureConversationBinding.Elements.Add(new TcpTransportBindingElement
            {
                MaxBufferSize = int.MaxValue,
                MaxReceivedMessageSize = int.MaxValue
            });
            return netTcpSecureConversationBinding;
        }
    }
    

    public static class Extensions
    {
        public static TChannel CreateChannelWithIssuedToken<TChannel>(this ChannelFactory<TChannel> factory, SecurityToken token)
        {
            SamlClientCredentials clientCredentials = new SamlClientCredentials(token);
            factory.Endpoint.EndpointBehaviors.Remove(typeof(ClientCredentials));
            factory.Endpoint.EndpointBehaviors.Add(clientCredentials);
            return factory.CreateChannel();
        }

        private class SamlSecurityTokenProvider : SecurityTokenProvider
        {
            private readonly SecurityToken _securityToken;

            public SamlSecurityTokenProvider(SecurityToken securityToken) => this._securityToken = securityToken;

            protected override SecurityToken GetTokenCore(TimeSpan timeout) => this._securityToken;
        }

        private class SamlSecurityTokenManager : ClientCredentialsSecurityTokenManager
        {
            private readonly SamlClientCredentials _samlClientCredentials;

            public SamlSecurityTokenManager(SamlClientCredentials samlClientCredentials) : base((ClientCredentials)samlClientCredentials)
            {
                this._samlClientCredentials = samlClientCredentials;
            }

            public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
            {
                if (IsSecureConversation(tokenRequirement))
                {
                    return base.CreateSecurityTokenProvider(tokenRequirement);
                }
                return new SamlSecurityTokenProvider(this._samlClientCredentials.SecurityToken);
            }

            private bool IsSecureConversation(SecurityTokenRequirement requirement) => requirement.TokenType == "http://schemas.microsoft.com/ws/2006/05/servicemodel/tokens/SecureConversation";
        }

        private class SamlClientCredentials : ClientCredentials
        {
            public SamlClientCredentials(SecurityToken securityToken) => this.SecurityToken = securityToken;

            private SamlClientCredentials(SamlClientCredentials other) : base((ClientCredentials)other)
            {
                this.SecurityToken = other.SecurityToken;
            }

            public SecurityToken SecurityToken { get; }

            protected override ClientCredentials CloneCore() => (ClientCredentials)new SamlClientCredentials(this);

            public override SecurityTokenManager CreateSecurityTokenManager() => (SecurityTokenManager)new SamlSecurityTokenManager(this);
        }
    }
}
