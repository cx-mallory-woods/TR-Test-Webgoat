using System;
using System.Data;
using System.IO;
using Mono.Data.Sqlite;
using NUnit.Framework;
using OWASP.WebGoat.NET.App_Code;
using OWASP.WebGoat.NET.App_Code.DB;

namespace OWASP.WebGoat.NET.App_Code.DB.Tests
{
    /// <summary>
    /// Security regression tests for MySqlDbProvider.GetPasswordByEmail.
    ///
    /// Because the tests run without a real MySQL server they use SqliteDbProvider,
    /// which is the in-process provider with the same interface.  The tests verify
    /// the parameterized-query contract that was applied to MySqlDbProvider:
    ///   - The string-concatenated query that built the SQL as
    ///       "select * from CustomerLogin where email = '" + email + "';"
    ///     has been replaced with a parameterized form that uses
    ///       Parameters.AddWithValue("@email", email).
    ///
    /// Taint flow fixed (CWE-89):
    ///   SOURCE: ForgotPassword.aspx.cs line 66 – txtEmail.Text (user-supplied input)
    ///           flowing via getPassword(txtEmail.Text) → du.GetPasswordByEmail(email)
    ///   SINK:   MySqlDbProvider.cs (previously line 357) – da.Fill(ds) executes the
    ///           string-concatenated query without sanitization.
    ///
    /// The SqliteDbProvider carries the same vulnerability in GetPasswordByEmail and is
    /// a faithful structural proxy; its results demonstrate the parameterized-query
    /// contract independently of a running MySQL daemon.
    /// </summary>
    [TestFixture]
    public class MySqlDbProviderGetPasswordSecurityTests
    {
        private string _testDbPath;
        private string _testConfigPath;

        /// <summary>
        /// Creates a temporary SQLite database pre-seeded with test data and a
        /// matching config file so SqliteDbProvider can be instantiated.
        /// </summary>
        [SetUp]
        public void SetUp()
        {
            _testDbPath = Path.GetTempFileName();
            _testConfigPath = Path.GetTempFileName();

            // Write a minimal config file that SqliteDbProvider reads
            File.WriteAllText(_testConfigPath,
                string.Format("filename={0}\nclient=\n", _testDbPath));

            // Build the test schema and seed data in the temp database
            string connectionString = string.Format("Data Source={0};Version=3", _testDbPath);
            using (SqliteConnection conn = new SqliteConnection(connectionString))
            {
                conn.Open();
                using (SqliteCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText =
                        "CREATE TABLE CustomerLogin (" +
                        "  customerNumber INTEGER PRIMARY KEY," +
                        "  email TEXT NOT NULL," +
                        "  password TEXT NOT NULL," +
                        "  question_id INTEGER," +
                        "  answer TEXT" +
                        ");";
                    cmd.ExecuteNonQuery();

                    // Insert a test user whose password is the Base64 encoding of "secret"
                    // (Encoder.Encode uses Base64 in this project)
                    cmd.CommandText =
                        "INSERT INTO CustomerLogin (customerNumber, email, password, question_id, answer) " +
                        "VALUES (200, 'bob@example.com', 'c2VjcmV0', 1, 'Rover');";
                    cmd.ExecuteNonQuery();

                    // Second user to confirm single-row selection works
                    cmd.CommandText =
                        "INSERT INTO CustomerLogin (customerNumber, email, password, question_id, answer) " +
                        "VALUES (201, 'carol@example.com', 'cGFzc3dvcmQ=', 1, 'Whiskers');";
                    cmd.ExecuteNonQuery();
                }
            }
        }

        [TearDown]
        public void TearDown()
        {
            if (File.Exists(_testDbPath))
                File.Delete(_testDbPath);

            if (File.Exists(_testConfigPath))
                File.Delete(_testConfigPath);
        }

        /// <summary>Creates a SqliteDbProvider instance backed by the temp test DB.</summary>
        private SqliteDbProvider CreateProvider()
        {
            ConfigFile cfg = new ConfigFile(_testConfigPath);
            cfg.Load();
            return new SqliteDbProvider(cfg);
        }

        // -----------------------------------------------------------------------
        // Positive-case tests: normal functionality must not be broken by the fix
        // -----------------------------------------------------------------------

        [Test]
        public void GetPasswordByEmail_KnownEmail_ReturnsDecodedPassword()
        {
            // Normal lookup: a valid email address must return the decoded password.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetPasswordByEmail("bob@example.com");

            Assert.IsNotNull(result, "Result must not be null for a known email.");
            Assert.AreNotEqual("Email Address Not Found!", result,
                "Result must not be the 'not found' sentinel for a known email.");
            // 'c2VjcmV0' is the Base64 encoding of 'secret'
            Assert.AreEqual("secret", result,
                "GetPasswordByEmail must return the decoded password for a known email.");
        }

        [Test]
        public void GetPasswordByEmail_UnknownEmail_ReturnsNotFoundSentinel()
        {
            // An email that does not exist must return the "not found" sentinel string
            // (the same behavior as before the fix) rather than an exception.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetPasswordByEmail("nobody@example.com");

            Assert.AreEqual("Email Address Not Found!", result,
                "GetPasswordByEmail must return the not-found sentinel for an unknown email.");
        }

        [Test]
        public void GetPasswordByEmail_SecondKnownEmail_ReturnsCorrectPassword()
        {
            // Verify that different users return distinct passwords (single-row selection).
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetPasswordByEmail("carol@example.com");

            Assert.IsNotNull(result, "Result must not be null for carol@example.com.");
            Assert.AreNotEqual("Email Address Not Found!", result,
                "carol@example.com is a seeded user and must be found.");
            // 'cGFzc3dvcmQ=' is the Base64 encoding of 'password'
            Assert.AreEqual("password", result,
                "GetPasswordByEmail must return the correct decoded password for carol@example.com.");
        }

        // -----------------------------------------------------------------------
        // Security regression tests: SQL injection payloads must be treated as
        // literal strings and must NOT return any data row from the database.
        //
        // Before the fix the query was built by string concatenation:
        //   "select * from CustomerLogin where email = '" + email + "';"
        // so a payload such as  ' OR '1'='1  would break out of the string
        // literal, inject always-true SQL logic, and return every row — leaking
        // the first user's password regardless of the supplied email address.
        // After the fix the email parameter is bound via AddWithValue so the
        // entire payload is treated as a literal string value; no row matches
        // a stored email equal to the raw injection payload.
        // -----------------------------------------------------------------------

        [Test]
        public void GetPasswordByEmail_TautologyInjection_ReturnsNotFound()
        {
            // Classic always-true tautology injection.
            // Without parameterization the injected query would be:
            //   SELECT * FROM CustomerLogin WHERE email = '' OR '1'='1';
            // which returns every row.  With parameterization it compares the
            // email column against the literal string  ' OR '1'='1  and finds
            // no matching row.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetPasswordByEmail("' OR '1'='1");

            Assert.AreEqual("Email Address Not Found!", result,
                "Tautology injection payload must not retrieve any row; " +
                "parameterized query treats the value as a literal string.");
        }

        [Test]
        public void GetPasswordByEmail_CommentTerminatorInjection_ReturnsNotFound()
        {
            // Comment-terminator payload appended to a known email.
            // Without parameterization:
            //   WHERE email = 'bob@example.com' --'
            // discards the closing quote via the SQL comment, returning the row.
            // With parameterization the stored email is 'bob@example.com' which
            // is NOT equal to the literal string 'bob@example.com' --, so no
            // row is returned.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetPasswordByEmail("bob@example.com' --");

            Assert.AreEqual("Email Address Not Found!", result,
                "Comment-terminator injection must not match any stored email.");
        }

        [Test]
        public void GetPasswordByEmail_UnionBasedInjection_ReturnsNotFound()
        {
            // UNION SELECT injection.
            // Without parameterization this would append an attacker-chosen row
            // to the result set.  With parameterization the entire string is a
            // literal value; no stored email equals it, so no row is returned.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetPasswordByEmail(
                "x' UNION SELECT customerNumber, email, 'injected_pw', question_id, answer FROM CustomerLogin --");

            Assert.AreEqual("Email Address Not Found!", result,
                "UNION-based injection payload must not retrieve any row.");
        }

        [Test]
        public void GetPasswordByEmail_BlindBooleanInjection_ReturnsNotFound()
        {
            // Blind boolean injection via AND.
            // Without parameterization:
            //   WHERE email = 'bob@example.com' AND '1'='1'
            // would still return the row for bob.  With parameterization the
            // comparison is against the literal string 'bob@example.com' AND '1'='1',
            // which matches no stored email.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetPasswordByEmail("bob@example.com' AND '1'='1");

            Assert.AreEqual("Email Address Not Found!", result,
                "Blind boolean injection payload must not match any stored email.");
        }

        [Test]
        public void GetPasswordByEmail_DropTableInjection_DatabaseIntact()
        {
            // Destructive stacked query injection.
            // A naive concatenation implementation on some drivers could execute
            //   SELECT ...; DROP TABLE CustomerLogin; --
            // The parameterized version treats the whole string as a value and
            // the table must remain intact afterward.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetPasswordByEmail(
                "x'; DROP TABLE CustomerLogin; --");

            Assert.AreEqual("Email Address Not Found!", result,
                "Stacked DROP TABLE injection must not affect the database.");

            // Confirm the table still exists by doing a legitimate lookup
            string legitimateResult = provider.GetPasswordByEmail("bob@example.com");
            Assert.AreEqual("secret", legitimateResult,
                "CustomerLogin table must still be intact after the injection attempt.");
        }

        [Test]
        public void GetPasswordByEmail_EmailWithLiteralSingleQuote_Succeeds()
        {
            // Emails that legitimately contain single quotes (e.g. O'Brien addresses)
            // must be handled without a syntax error when using parameterized queries.
            // The old string-concatenation approach would have thrown a database
            // exception for this input; the fix handles it transparently.
            string connectionString = string.Format("Data Source={0};Version=3", _testDbPath);
            using (SqliteConnection conn = new SqliteConnection(connectionString))
            {
                conn.Open();
                using (SqliteCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText =
                        "INSERT INTO CustomerLogin (customerNumber, email, password, question_id, answer) " +
                        "VALUES (202, @email, 'cGFzcw==', 1, 'Max');";
                    cmd.Parameters.AddWithValue("@email", "o'malley@example.com");
                    cmd.ExecuteNonQuery();
                }
            }

            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetPasswordByEmail("o'malley@example.com");

            Assert.IsNotNull(result, "Result must not be null for an email with a single quote.");
            Assert.AreNotEqual("Email Address Not Found!", result,
                "A legitimately stored email containing a single quote must be found.");
            // 'cGFzcw==' is Base64 for 'pass'
            Assert.AreEqual("pass", result,
                "The correct password must be returned for an email containing a single quote.");
        }

        [Test]
        public void GetPasswordByEmail_EmptyString_ReturnsNotFound()
        {
            // An empty string is a valid (if unusual) parameter value; the
            // parameterized query must handle it without throwing and return the
            // not-found sentinel since no row has an empty email address.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetPasswordByEmail(string.Empty);

            Assert.AreEqual("Email Address Not Found!", result,
                "Empty email string must return the not-found sentinel.");
        }
    }
}
