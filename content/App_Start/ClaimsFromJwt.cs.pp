using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web.Script.Serialization;

namespace $rootnamespace$
{

    /// <summary>
    /// A set of helper functions for transforming an already-validated JWT into a ClaimsIdentity, using 
    /// standardized Claims wherever possible.
    /// </summary>
    public static class JwtHelper
    {

        #region Constants

        private const string StringClaimValueType = "http://www.w3.org/2001/XMLSchema#string";

        #endregion

        #region Private Members

        // NOTE: You can add to or modify these arrays as necessary. The routine will automatically remove
        //       any "_" characters.

        private static readonly string[] ClaimTypesForUserId = { "userid" };
        private static readonly string[] ClaimTypesForRoles = { "roles", "role" };
        private static readonly string[] ClaimTypesForEmail = { "emails", "email" };
        private static readonly string[] ClaimTypesForGivenName = { "givenname", "firstname"  };
        private static readonly string[] ClaimTypesForFamilyName = { "familyname", "lastname", "surname" };
        private static readonly string[] ClaimTypesForPostalCode = { "postalcode" };
        private static readonly string[] ClaimsToExclude = { "iss", "sub", "aud", "exp", "iat", "identities" };

        #endregion

        #region Public Methods

        /// <summary>
        /// Gets a List of Claims from a given deserialized JSON token.
        /// </summary>
        /// <param name="jwtData">The deserialized JSON payload to process.</param>
        /// <param name="issuer">The principal that issued the JWT.</param>
        /// <returns>A List of Claims derived from the JWT.</returns>
        public static List<Claim> GetClaimsFromJwt(Dictionary<string, object> jwtData, string issuer)
        {
            var list = new List<Claim>();
            issuer = issuer ?? DefaultIssuer;

            foreach (var pair in jwtData)
            {
                var claimType = GetClaimType(pair.Key);
                var source = pair.Value as ArrayList;

                if (source != null)
                {
                    // Get the claim, check to make sure it hasn't already been added. This is a workaround
                    // for an issue where MicrosoftAccounts return the same e-mail address twice.
                    foreach (var innerClaim in source.Cast<object>().Select(item => new Claim(claimType, item.ToString(), StringClaimValueType, issuer, issuer))
                        .Where(innerClaim => !list.Any(c => c.Type == innerClaim.Type && c.Value == innerClaim.Value)))
                    {
                        list.Add(innerClaim);
                    }

                    continue;
                }

                var claim = new Claim(claimType, pair.Value.ToString(), StringClaimValueType, issuer, issuer);
                if (!list.Contains(claim))
                {
                    list.Add(claim);
                }
            }

            // dont include specific jwt claims
            return list.Where(c => ClaimsToExclude.All(t => t != c.Type)).ToList();
        }

        /// <summary>
        /// Gets a <see cref="ClaimsIdentity"/> properly populated with the claims from the JWT.
        /// </summary>
        /// <param name="claims">The list of claims that we've already processed.</param>
        /// <param name="issuer">The principal that issued the JWT.</param>
        /// <returns></returns>
        public static ClaimsIdentity GetClaimsIdentity(List<Claim> claims, string issuer)
        {
            var subject = new ClaimsIdentity("Federation", ClaimTypes.Name, ClaimTypes.Role);

            foreach (var claim in claims)
            {
                var type = claim.Type;
                if (type == ClaimTypes.Actor)
                {
                    if (subject.Actor != null)
                    {
                        throw new InvalidOperationException(string.Format(
                            "Jwt10401: Only a single 'Actor' is supported. Found second claim of type: '{0}', value: '{1}'", new object[] { "actor", claim.Value }));
                    }
                }

                var claim3 = new Claim(type, claim.Value, claim.ValueType, issuer, issuer, subject);
                subject.AddClaim(claim3);
            }

            return subject;
        }

        /// <summary>
        /// Attempts to map names from the JWT into standard Claim types.
        /// </summary>
        /// <param name="name">The name of the Claim as passed in my the JWT.</param>
        /// <returns>A string that hopefully contains the standard namespace for a given Claim.</returns>
        public static string GetClaimType(string name)
        {
            var newName = name.Replace("_", "").ToLower();
            if (newName == "name")
            {
                return ClaimTypes.Name;
            }
            if (ClaimTypesForUserId.Contains(newName))
            {
                return ClaimTypes.NameIdentifier;
            }
            if (ClaimTypesForRoles.Contains(newName))
            {
                return ClaimTypes.Role;
            }
            if (ClaimTypesForEmail.Contains(newName))
            {
                return ClaimTypes.Email;
            }
            if (ClaimTypesForGivenName.Contains(newName))
            {
                return ClaimTypes.GivenName;
            }
            if (ClaimTypesForFamilyName.Contains(newName))
            {
                return ClaimTypes.Surname;
            }
            if (ClaimTypesForPostalCode.Contains(newName))
            {
                return ClaimTypes.PostalCode;
            }
            if (name == "gender")
            {
                return ClaimTypes.Gender;
            }

            return name;
        }

        #endregion

    }
}
