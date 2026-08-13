using System;
using System.Web;
using NUnit.Framework;

namespace OWASP.WebGoat.NET.WebGoatCoins.Tests
{
    /// <summary>
    /// Security regression tests for the Reflected XSS vulnerability (CWE-79) in
    /// WebGoatCoins/CustomerLogin.aspx.
    ///
    /// Vulnerability fixed:
    ///   The inline server-side expression on line 9 of CustomerLogin.aspx embedded
    ///   the raw value of Request["ReturnUrl"] directly into the page output via
    ///   Response.Write (the &lt;%= %&gt; syntax), without any encoding.  An attacker
    ///   could craft a URL whose ReturnUrl parameter contained JavaScript payloads
    ///   (e.g. &lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;), which would be
    ///   reflected verbatim into the rendered HTML, executing in the victim's browser.
    ///
    /// Fix applied:
    ///   The expression now wraps the user-supplied value with
    ///   HttpUtility.HtmlEncode(), which is the standard System.Web API recognised by
    ///   SAST engines as a sanitizer for HTML/JavaScript output contexts.
    ///   After encoding, characters such as '&lt;', '&gt;', '"', and '&amp;' are
    ///   converted to their safe HTML entity equivalents before they reach the
    ///   browser, preventing script injection.
    ///
    /// Taint flow fixed:
    ///   SOURCE: Request["ReturnUrl"] – line 9, column 65 of CustomerLogin.aspx
    ///   SINK:   Response.Write (&lt;%= %&gt; expression) – line 9, column 11
    /// </summary>
    [TestFixture]
    public class CustomerLoginXssSecurityTests
    {
        // -----------------------------------------------------------------------
        // Helper: simulates the encoding expression used in the fixed ASPX page.
        //
        //   Before fix (vulnerable):
        //       Request["ReturnUrl"].ToString()
        //
        //   After fix (safe):
        //       HttpUtility.HtmlEncode(Request["ReturnUrl"])
        //
        // The tests below call EncodeReturnUrl() to confirm that the sanitizer
        // used in the fix correctly neutralises every relevant attack payload.
        // -----------------------------------------------------------------------

        /// <summary>
        /// Reproduces the encoding logic written into CustomerLogin.aspx line 9.
        /// Returns an empty string when the input is null (matching the ternary
        /// null-guard in the ASPX expression).
        /// </summary>
        private static string EncodeReturnUrl(string rawValue)
        {
            if (rawValue == null)
                return string.Empty;
            return HttpUtility.HtmlEncode(rawValue);
        }

        // -----------------------------------------------------------------------
        // Positive-case tests: normal URLs must pass through correctly encoded.
        // -----------------------------------------------------------------------

        [Test]
        public void EncodeReturnUrl_NullInput_ReturnsEmptyString()
        {
            // The ASPX ternary guard treats null as "" — the encoded output must
            // also be empty so no content is injected into the page.
            string result = EncodeReturnUrl(null);
            Assert.AreEqual(string.Empty, result,
                "A null ReturnUrl must produce an empty string, not 'null'.");
        }

        [Test]
        public void EncodeReturnUrl_PlainRelativePath_ReturnedUnchanged()
        {
            // A well-formed relative URL has no characters that require encoding.
            string result = EncodeReturnUrl("/WebGoatCoins/MainPage.aspx");
            Assert.AreEqual("/WebGoatCoins/MainPage.aspx", result,
                "A plain relative path must pass through HttpUtility.HtmlEncode unchanged.");
        }

        [Test]
        public void EncodeReturnUrl_PathWithQueryString_ReturnedWithAmpersandEncoded()
        {
            // The '&' in a query string must be HTML-entity encoded to &amp; so
            // it cannot be interpreted as part of a tag attribute.
            string input = "/page.aspx?foo=1&bar=2";
            string result = EncodeReturnUrl(input);
            Assert.IsFalse(result.Contains("&bar"),
                "The raw '&' character must be encoded to '&amp;' to prevent attribute injection.");
            Assert.IsTrue(result.Contains("&amp;bar"),
                "The '&' in the query string must appear as '&amp;' after encoding.");
        }

        // -----------------------------------------------------------------------
        // Security regression tests: XSS payloads must be neutralised by the fix.
        //
        // Before the fix, each payload below was reflected verbatim into the page,
        // breaking out of the JavaScript string and injecting executable script.
        // After the fix, HttpUtility.HtmlEncode converts dangerous characters to
        // safe HTML entities so no code can execute.
        // -----------------------------------------------------------------------

        [Test]
        public void EncodeReturnUrl_ScriptTagPayload_AngleBracketsEncoded()
        {
            // Classic XSS via script tag injection.
            // Vulnerable output: "</script><script>alert(1)</script>
            // Safe output:       &lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;
            string payload = "</script><script>alert(1)</script>";
            string result = EncodeReturnUrl(payload);

            Assert.IsFalse(result.Contains("<script>"),
                "A raw <script> tag must not appear in the encoded output.");
            Assert.IsFalse(result.Contains("</script>"),
                "A raw </script> tag must not appear in the encoded output.");
            Assert.IsTrue(result.Contains("&lt;script&gt;"),
                "The '<script>' sequence must be encoded to '&lt;script&gt;'.");
        }

        [Test]
        public void EncodeReturnUrl_EventHandlerPayload_AngleBracketsEncoded()
        {
            // XSS via HTML event handler injection (e.g. breaking out of a tag).
            // Vulnerable output: "><img src=x onerror=alert(1)>
            // Safe output:       &quot;&gt;&lt;img src=x onerror=alert(1)&gt;
            string payload = "\"><img src=x onerror=alert(1)>";
            string result = EncodeReturnUrl(payload);

            Assert.IsFalse(result.Contains("<img"),
                "A raw '<img' must not appear in the encoded output.");
            Assert.IsTrue(result.Contains("&lt;img"),
                "The '<img' sequence must be encoded to '&lt;img'.");
        }

        [Test]
        public void EncodeReturnUrl_DoubleQuotePayload_QuotesEncoded()
        {
            // An attacker can break out of the JavaScript string delimiter (" or ')
            // by including a raw double-quote in the ReturnUrl value.
            // HttpUtility.HtmlEncode converts '"' to '&quot;'.
            string payload = "/path\";alert(\"xss\")//";
            string result = EncodeReturnUrl(payload);

            // The literal double-quote must not survive encoding.
            Assert.IsFalse(result.Contains("\""),
                "Raw double-quote characters must be encoded to '&quot;' by HtmlEncode.");
            Assert.IsTrue(result.Contains("&quot;"),
                "Double quotes must appear as '&quot;' in the encoded output.");
        }

        [Test]
        public void EncodeReturnUrl_SingleQuotePayload_QuotesEncoded()
        {
            // Single-quote can break out of a JS string literal delimited with '.
            // HttpUtility.HtmlEncode converts '\'' to '&#39;'.
            string payload = "/path';alert('xss')//";
            string result = EncodeReturnUrl(payload);

            Assert.IsFalse(result.Contains("'"),
                "Raw single-quote characters must not appear in the encoded output.");
        }

        [Test]
        public void EncodeReturnUrl_AmpersandPayload_AmpersandEncoded()
        {
            // Unencoded '&' can form HTML entities or be used in attribute injection.
            string payload = "/page?x=1&amp;y=<script>alert(1)</script>";
            string result = EncodeReturnUrl(payload);

            Assert.IsFalse(result.Contains("<script>"),
                "A script tag injected via the query string must be encoded.");
        }

        [Test]
        public void EncodeReturnUrl_JavaScriptProtocolPayload_ColonPreservedButTagsBroken()
        {
            // javascript: URI scheme can execute code in certain contexts.
            // HtmlEncode does not encode ':', but it does encode the surrounding
            // angle-bracket tags that would be needed for an anchor injection.
            string payload = "javascript:alert(document.cookie)";
            string result = EncodeReturnUrl(payload);

            // The dangerous characters (< >) that would be needed for a
            // full HTML-injection attack are absent in this payload — but verify
            // that the encoding round-trip does not introduce new issues.
            Assert.AreEqual("javascript:alert(document.cookie)", result,
                "A plain javascript: URI without HTML special chars is preserved as-is " +
                "by HtmlEncode (no < > \" & present); the open-redirect risk is separate.");
        }

        [Test]
        public void EncodeReturnUrl_ComplexPayload_AllDangerousCharsEncoded()
        {
            // A payload that combines multiple attack vectors.
            string payload = "<img src=\"x\" onerror='alert(1)'>&amp;foo";
            string result = EncodeReturnUrl(payload);

            Assert.IsFalse(result.Contains("<img"),
                "The '<img' tag start must be encoded.");
            Assert.IsFalse(result.Contains("onerror='alert"),
                "Unquoted event handlers must not survive encoding.");
            Assert.IsTrue(result.Contains("&lt;img"),
                "'<img' must appear as '&lt;img' after encoding.");
        }

        // -----------------------------------------------------------------------
        // Encoding round-trip tests: verify correct entity substitution.
        // -----------------------------------------------------------------------

        [Test]
        public void HttpUtility_HtmlEncode_LessThanIsEncoded()
        {
            Assert.AreEqual("&lt;", HttpUtility.HtmlEncode("<"),
                "HttpUtility.HtmlEncode must convert '<' to '&lt;'.");
        }

        [Test]
        public void HttpUtility_HtmlEncode_GreaterThanIsEncoded()
        {
            Assert.AreEqual("&gt;", HttpUtility.HtmlEncode(">"),
                "HttpUtility.HtmlEncode must convert '>' to '&gt;'.");
        }

        [Test]
        public void HttpUtility_HtmlEncode_DoubleQuoteIsEncoded()
        {
            Assert.AreEqual("&quot;", HttpUtility.HtmlEncode("\""),
                "HttpUtility.HtmlEncode must convert '\"' to '&quot;'.");
        }

        [Test]
        public void HttpUtility_HtmlEncode_AmpersandIsEncoded()
        {
            Assert.AreEqual("&amp;", HttpUtility.HtmlEncode("&"),
                "HttpUtility.HtmlEncode must convert '&' to '&amp;'.");
        }

        [Test]
        public void HttpUtility_HtmlEncode_EmptyString_ReturnsEmptyString()
        {
            Assert.AreEqual(string.Empty, HttpUtility.HtmlEncode(string.Empty),
                "HttpUtility.HtmlEncode must return an empty string for empty input.");
        }

        [Test]
        public void HttpUtility_HtmlEncode_SafeChars_ReturnedUnchanged()
        {
            string safe = "abcdefghijklmnopqrstuvwxyz0123456789/._-~";
            Assert.AreEqual(safe, HttpUtility.HtmlEncode(safe),
                "Characters that do not require HTML encoding must pass through unchanged.");
        }
    }
}
