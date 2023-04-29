using DotnetWcfIssueReproService;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Xml;

namespace DotnetWcfIssueReproServiceHost
{
    internal class Program
    {
        static void Main(string[] args)
        {
            using (ServiceHost host = new ServiceHost(typeof(Service)))
            {
                host.Description.Behaviors.Find<ServiceCredentials>().IdentityConfiguration.SecurityTokenHandlers.AddOrReplace(new CustomSaml2SecurityTokenHandler());
                host.Open();

                Console.WriteLine("Host listening ...");
                Console.ReadLine();
            }
        }
    }

    public class CustomSaml2SecurityTokenHandler : Saml2SecurityTokenHandler
    {
        public override SecurityToken ReadToken(XmlReader reader, SecurityTokenResolver tokenResolver)
        {
            return new Saml2SecurityToken(base.ReadAssertion(reader), 
                new List<SecurityKey> { new InMemorySymmetricSecurityKey(Convert.FromBase64String("PJC7HnliwcxXw4FM8Ep3sX9NIL3R5CZnDvp8IyyCSlg=")) }.AsReadOnly(), 
                null);
        }

        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {
            return new List<ClaimsIdentity>(1)
            {
                new ClaimsIdentity("Federation", this.SamlSecurityTokenRequirement.NameClaimType, this.SamlSecurityTokenRequirement.RoleClaimType)
            }.AsReadOnly();
        }
    }
}
