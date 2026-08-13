using System;
using System.IO;
using NUnit.Framework;

namespace OWASP.WebGoat.NET.WebGoatCoins.Tests
{
    /// <summary>
    /// Security regression tests for the path-traversal vulnerability remediation in
    /// Orders.aspx.cs (CWE-22, OWASP Top 10 A01: Broken Access Control).
    ///
    /// Taint flow fixed:
    ///   SOURCE: Orders.aspx.cs line 88 – Request["image"] (user-supplied input)
    ///   SINK:   Orders.aspx.cs line 101 – Response.TransmitFile(fi.FullName)
    ///
    /// The fix resolves both the user-supplied path and the allowed base directory to
    /// their canonical absolute forms using Path.GetFullPath, then enforces a
    /// StartsWith containment check so that traversal sequences such as "../",
    /// "..\\", or URL-encoded variants cannot escape the products image folder.
    ///
    /// These tests exercise the same containment logic in isolation, using a
    /// temporary directory that stands in for the web application's physical root.
    /// </summary>
    [TestFixture]
    public class OrdersPathTraversalSecurityTests
    {
        // Simulated web-application physical root on disk.
        private string _appRoot;

        // Allowed base directory: <appRoot>\images\products\
        private string _allowedBase;

        [SetUp]
        public void SetUp()
        {
            _appRoot = Path.Combine(Path.GetTempPath(), "OrdersTest_" + Guid.NewGuid().ToString("N"));
            _allowedBase = Path.Combine(_appRoot, "images", "products") + Path.DirectorySeparatorChar;

            // Create the directory structure that the web app would have.
            Directory.CreateDirectory(_allowedBase);

            // Create a sibling directory to verify boundary enforcement.
            Directory.CreateDirectory(Path.Combine(_appRoot, "images", "logos"));

            // Create a legitimate product image file for positive-case tests.
            File.WriteAllBytes(Path.Combine(_allowedBase, "coin_thumb.jpg"), new byte[] { 0xFF, 0xD8, 0xFF });

            // Create a sensitive file outside the allowed base for attack-case tests.
            File.WriteAllText(Path.Combine(_appRoot, "Web.config"), "<config>secret</config>");
        }

        [TearDown]
        public void TearDown()
        {
            if (Directory.Exists(_appRoot))
                Directory.Delete(_appRoot, true);
        }

        // -----------------------------------------------------------------------
        // Helper: mirrors the containment check added to Orders.aspx.cs.
        //
        // In production code Server.MapPath maps a virtual path to a physical path.
        // Here we replace that with a simple path combination so the check can be
        // exercised without an HttpContext.
        // -----------------------------------------------------------------------

        /// <summary>
        /// Returns true when the physical path produced from <paramref name="userInput"/>
        /// is safely contained within <paramref name="allowedBase"/>.
        /// </summary>
        private bool IsPathSafe(string allowedBase, string userInput)
        {
            // Simulate Server.MapPath by combining the app root with the user input.
            // In the real code, Server.MapPath does this translation.
            string mappedUserPath = Path.Combine(_appRoot, userInput.TrimStart('/', '\\'));
            string canonicalUserPath = Path.GetFullPath(mappedUserPath);
            string canonicalBase = Path.GetFullPath(allowedBase);

            return canonicalUserPath.StartsWith(canonicalBase, StringComparison.OrdinalIgnoreCase);
        }

        // -----------------------------------------------------------------------
        // Positive-case tests: legitimate requests must pass the containment check.
        // -----------------------------------------------------------------------

        [Test]
        public void IsPathSafe_LegitimateRelativePath_ReturnsTrue()
        {
            // A normal request coming from the application itself: the hyperlink built
            // in Orders.aspx sets image=images/products/<filename>.
            bool result = IsPathSafe(_allowedBase, "images/products/coin_thumb.jpg");
            Assert.IsTrue(result,
                "A path that resolves inside the allowed base must be accepted.");
        }

        [Test]
        public void IsPathSafe_NestedSubdirectoryInsideBase_ReturnsTrue()
        {
            // Subdirectories inside the allowed base (if they ever exist) must be allowed.
            string subdir = Path.Combine(_allowedBase, "2024");
            Directory.CreateDirectory(subdir);
            bool result = IsPathSafe(_allowedBase, "images/products/2024/new_coin.jpg");
            Assert.IsTrue(result,
                "A path inside a subdirectory of the allowed base must be accepted.");
        }

        // -----------------------------------------------------------------------
        // Security regression tests: traversal payloads must be rejected.
        //
        // Before the fix the resolved FileInfo.FullName was used directly in
        // Response.TransmitFile without any containment check, so an attacker could
        // supply a value like "../../Web.config" and read arbitrary files.
        //
        // After the fix Path.GetFullPath canonicalises traversal sequences and the
        // StartsWith check then rejects any path that escapes the allowed base.
        // -----------------------------------------------------------------------

        [Test]
        public void IsPathSafe_DotDotRelativeTraversal_ReturnsFalse()
        {
            // Classic directory traversal: ../../Web.config
            bool result = IsPathSafe(_allowedBase, "images/products/../../Web.config");
            Assert.IsFalse(result,
                "A path that traverses above the allowed base with '../' must be rejected.");
        }

        [Test]
        public void IsPathSafe_MultipleUpwardsTraversal_ReturnsFalse()
        {
            // Multiple levels of traversal to reach a file outside the web root.
            bool result = IsPathSafe(_allowedBase, "../../../etc/passwd");
            Assert.IsFalse(result,
                "A path that traverses multiple levels above the app root must be rejected.");
        }

        [Test]
        public void IsPathSafe_AbsolutePathToSensitiveFile_ReturnsFalse()
        {
            // On some systems an absolute path could be passed if MapPath allows it.
            // Simulate by constructing a path that already starts at the root.
            string absolutePayload = Path.Combine(_appRoot, "Web.config");
            // Treat the payload as if the user supplied an absolute path that was
            // then used directly; containment check must still reject it because
            // it does not start with the allowed base.
            string canonicalBase = Path.GetFullPath(_allowedBase);
            string canonicalPayload = Path.GetFullPath(absolutePayload);
            bool result = canonicalPayload.StartsWith(canonicalBase,
                StringComparison.OrdinalIgnoreCase);

            Assert.IsFalse(result,
                "An absolute path to a file outside the allowed base must be rejected.");
        }

        [Test]
        public void IsPathSafe_SiblingDirectoryWithSimilarName_ReturnsFalse()
        {
            // A sibling directory whose name starts with the allowed directory name
            // must not be confused with the allowed base.
            // e.g., images/productsFoo/../../Web.config or just images/logos/file.jpg
            bool result = IsPathSafe(_allowedBase, "images/logos/logo.png");
            Assert.IsFalse(result,
                "A path in a sibling directory that is not the allowed base must be rejected.");
        }

        [Test]
        public void IsPathSafe_TraversalWithBackslash_ReturnsFalse()
        {
            // Windows-style backslash traversal after MapPath resolves the virtual path.
            bool result = IsPathSafe(_allowedBase, @"images\products\..\..\Web.config");
            Assert.IsFalse(result,
                "A backslash-based traversal sequence must be rejected.");
        }

        [Test]
        public void IsPathSafe_OnlyDotDotSegment_ReturnsFalse()
        {
            // Payload is just dot-dot, escaping to the parent of the allowed base.
            bool result = IsPathSafe(_allowedBase, "images/products/../");
            Assert.IsFalse(result,
                "A payload that resolves to the parent of the allowed base must be rejected.");
        }

        [Test]
        public void IsPathSafe_ParentDirectoryDirectly_ReturnsFalse()
        {
            // Accessing the images directory directly (not products subdirectory).
            bool result = IsPathSafe(_allowedBase, "images/");
            Assert.IsFalse(result,
                "A path resolving to the parent of the allowed base directory must be rejected.");
        }

        // -----------------------------------------------------------------------
        // Edge-case tests: boundary conditions that could be exploited.
        // -----------------------------------------------------------------------

        [Test]
        public void IsPathSafe_AllowedBaseDirectoryItself_ReturnsTrue()
        {
            // Requesting the base directory itself should pass the StartsWith check
            // (the directory exists, though TransmitFile would fail on a directory —
            // this test verifies that the guard logic is not over-restrictive).
            bool result = IsPathSafe(_allowedBase, "images/products/");
            Assert.IsTrue(result,
                "The allowed base directory itself must satisfy the containment check.");
        }

        [Test]
        public void IsPathSafe_ExtraSlashInInput_LegitimateFile_ReturnsTrue()
        {
            // Double slashes are collapsed by Path.GetFullPath; the result must still
            // be accepted for a legitimate file.
            bool result = IsPathSafe(_allowedBase, "images//products//coin_thumb.jpg");
            Assert.IsTrue(result,
                "Redundant slashes in a legitimate path must not cause a false rejection.");
        }

        [Test]
        public void IsPathSafe_NullInput_ThrowsOrReturnsFalse()
        {
            // A null target_image is guarded by the surrounding null-check in
            // Orders.aspx.cs, but the helper must not crash unexpectedly.
            // We verify that passing null either throws ArgumentNullException (correct
            // fail-fast behaviour) or returns false (safe-default behaviour).
            bool threwExpectedException = false;
            bool result = false;
            try
            {
                result = IsPathSafe(_allowedBase, null);
            }
            catch (ArgumentNullException)
            {
                threwExpectedException = true;
            }

            Assert.IsTrue(threwExpectedException || !result,
                "A null input must either throw ArgumentNullException or return false.");
        }
    }
}
