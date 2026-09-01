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
    /// Security regression tests for SqliteDbProvider.GetSecurityQuestionAndAnswer.
    ///
    /// These tests verify that the SQL injection vulnerability (CWE-89) has been
    /// properly remediated by replacing the string-concatenated query with a
    /// parameterized query that uses SqliteCommand.Parameters.AddWithValue.
    ///
    /// Taint flow fixed:
    ///   SOURCE: ForgotPassword.aspx.cs line 27 – txtEmail.Text (user-supplied input)
    ///   SINK:   SqliteDbProvider.cs line 310 – da.Fill(ds) executes the unsafe query
    /// </summary>
    [TestFixture]
    public class SqliteDbProviderSecurityTests
    {
        private string _testDbPath;
        private string _testConfigPath;

        /// <summary>
        /// Creates a temp SQLite database pre-seeded with test data and a
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
                        "CREATE TABLE SecurityQuestions (" +
                        "  question_id INTEGER PRIMARY KEY," +
                        "  question_text TEXT NOT NULL" +
                        ");";
                    cmd.ExecuteNonQuery();

                    cmd.CommandText =
                        "CREATE TABLE CustomerLogin (" +
                        "  customerNumber INTEGER PRIMARY KEY," +
                        "  email TEXT NOT NULL," +
                        "  password TEXT NOT NULL," +
                        "  question_id INTEGER," +
                        "  answer TEXT" +
                        ");";
                    cmd.ExecuteNonQuery();

                    cmd.CommandText =
                        "INSERT INTO SecurityQuestions (question_id, question_text) " +
                        "VALUES (1, 'What is the name of your first pet?');";
                    cmd.ExecuteNonQuery();

                    cmd.CommandText =
                        "INSERT INTO CustomerLogin (customerNumber, email, password, question_id, answer) " +
                        "VALUES (100, 'alice@example.com', 'secret', 1, 'Fluffy');";
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
        public void GetSecurityQuestionAndAnswer_KnownEmail_ReturnsQuestion()
        {
            SqliteDbProvider provider = CreateProvider();
            string[] result = provider.GetSecurityQuestionAndAnswer("alice@example.com");

            Assert.IsNotNull(result, "Result array must not be null.");
            Assert.AreEqual(2, result.Length, "Result array must have exactly 2 elements.");
            Assert.AreEqual("What is the name of your first pet?", result[0],
                "First element must be the security question text.");
        }

        [Test]
        public void GetSecurityQuestionAndAnswer_KnownEmail_ReturnsAnswer()
        {
            SqliteDbProvider provider = CreateProvider();
            string[] result = provider.GetSecurityQuestionAndAnswer("alice@example.com");

            Assert.IsNotNull(result);
            Assert.AreEqual("Fluffy", result[1],
                "Second element must be the stored security-question answer.");
        }

        [Test]
        public void GetSecurityQuestionAndAnswer_UnknownEmail_ReturnsNullSlots()
        {
            SqliteDbProvider provider = CreateProvider();
            string[] result = provider.GetSecurityQuestionAndAnswer("nobody@example.com");

            Assert.IsNotNull(result, "Result array must not be null for an unknown email.");
            Assert.IsNull(result[0],
                "Question slot must be null when the email is not found.");
            Assert.IsNull(result[1],
                "Answer slot must be null when the email is not found.");
        }

        // -----------------------------------------------------------------------
        // Security regression tests: SQL injection payloads must be treated as
        // literal strings and must NOT return any data row from the database.
        //
        // Before the fix the query was built by concatenation:
        //   "... where CustomerLogin.email = '" + email + "' ..."
        // so a payload such as  ' OR '1'='1  would escape the quote, inject SQL
        // logic, and return every row.  After the fix the email parameter is
        // bound via AddWithValue so the whole payload is a literal string value.
        // -----------------------------------------------------------------------

        [Test]
        public void GetSecurityQuestionAndAnswer_TautologyInjection_ReturnsEmpty()
        {
            // Classic always-true tautology: if concatenated directly this would
            // produce  WHERE email = '' OR '1'='1' ...  and return every row.
            SqliteDbProvider provider = CreateProvider();
            string[] result = provider.GetSecurityQuestionAndAnswer("' OR '1'='1");

            Assert.IsNull(result[0],
                "Tautology injection payload must not retrieve any row; " +
                "parameterized query treats the value as a literal string.");
        }

        [Test]
        public void GetSecurityQuestionAndAnswer_UnionBasedInjection_ReturnsEmpty()
        {
            // UNION SELECT injection: if concatenated directly this would append a
            // second result set with attacker-chosen values.
            SqliteDbProvider provider = CreateProvider();
            string[] result = provider.GetSecurityQuestionAndAnswer(
                "x' UNION SELECT 'injected', 'data' --");

            Assert.IsNull(result[0],
                "UNION-based injection payload must not retrieve any row.");
        }

        [Test]
        public void GetSecurityQuestionAndAnswer_CommentTerminatorInjection_NoMatch()
        {
            // Payload appends a SQL comment to discard the remainder of the query.
            // With parameterization the stored email is 'alice@example.com' which
            // is NOT equal to the literal string 'alice@example.com' --', so no
            // row must be returned.
            SqliteDbProvider provider = CreateProvider();
            string[] result = provider.GetSecurityQuestionAndAnswer(
                "alice@example.com' --");

            Assert.IsNull(result[0],
                "Comment-terminator injection must not match the stored email.");
        }

        [Test]
        public void GetSecurityQuestionAndAnswer_BlindBooleanInjection_ReturnsEmpty()
        {
            // Blind boolean injection via AND 1=1: if concatenated this could leak
            // whether a row exists by altering the WHERE predicate.
            SqliteDbProvider provider = CreateProvider();
            string[] result = provider.GetSecurityQuestionAndAnswer(
                "alice@example.com' AND '1'='1");

            Assert.IsNull(result[0],
                "Blind boolean injection payload must not match any stored email.");
        }

        [Test]
        public void GetSecurityQuestionAndAnswer_EmailWithLiteralSingleQuote_Succeeds()
        {
            // Emails that legitimately contain single quotes (e.g. O'Brien) must be
            // handled without a syntax error by the parameterized query.  This is a
            // correctness regression test: the old concatenation approach would have
            // thrown a SqliteException for this input.
            string connectionString = string.Format("Data Source={0};Version=3", _testDbPath);
            using (SqliteConnection conn = new SqliteConnection(connectionString))
            {
                conn.Open();
                using (SqliteCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText =
                        "INSERT INTO CustomerLogin (customerNumber, email, password, question_id, answer) " +
                        "VALUES (101, @email, 'pw', 1, 'Spot');";
                    cmd.Parameters.AddWithValue("@email", "o'brien@example.com");
                    cmd.ExecuteNonQuery();
                }
            }

            SqliteDbProvider provider = CreateProvider();
            string[] result = provider.GetSecurityQuestionAndAnswer("o'brien@example.com");

            Assert.IsNotNull(result, "Result must not be null for an email containing a single quote.");
            Assert.AreEqual("What is the name of your first pet?", result[0],
                "Question must be returned for a legitimate email address containing a single quote.");
            Assert.AreEqual("Spot", result[1],
                "Answer must be returned for a legitimate email address containing a single quote.");
        }

        [Test]
        public void GetSecurityQuestionAndAnswer_EmptyString_ReturnsNullSlots()
        {
            // An empty string is a valid (if unusual) parameter value; the
            // parameterized query must handle it without throwing.
            SqliteDbProvider provider = CreateProvider();
            string[] result = provider.GetSecurityQuestionAndAnswer(string.Empty);

            Assert.IsNotNull(result);
            Assert.IsNull(result[0],
                "Empty email should return null question slot.");
        }

        // -----------------------------------------------------------------------
        // Security regression tests for GetEmailByCustomerNumber (CWE-89).
        //
        // Taint flow fixed:
        //   SOURCE: SQLInjectionDiscovery.aspx.cs line 27 – txtID.Text (user input)
        //           → name = txtID.Text.Substring(0, 3)
        //           → du.GetEmailByCustomerNumber(name)
        //   SINK:   SqliteDbProvider.cs (previously line 521-522) –
        //           string-concatenated query passed to SqliteCommand / ExecuteScalar.
        //
        // Before the fix the query was built by string concatenation:
        //   "select email from CustomerLogin where customerNumber = " + num
        // so an attacker could inject arbitrary SQL via the num parameter.
        // After the fix the value is bound via Parameters.AddWithValue so the
        // entire payload is treated as a literal data value.
        // -----------------------------------------------------------------------

        [Test]
        public void GetEmailByCustomerNumber_KnownCustomerNumber_ReturnsEmail()
        {
            // Positive case: a valid customer number must return the seeded email.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetEmailByCustomerNumber("100");

            Assert.AreEqual("alice@example.com", result,
                "GetEmailByCustomerNumber must return the stored email for a known customer number.");
        }

        [Test]
        public void GetEmailByCustomerNumber_UnknownCustomerNumber_ReturnsNullOrEmpty()
        {
            // An integer customer number that does not exist in the database must
            // return null (ExecuteScalar returns null when no rows match).
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetEmailByCustomerNumber("9999");

            Assert.IsTrue(result == null || result == string.Empty,
                "GetEmailByCustomerNumber must return null or empty for an unknown customer number.");
        }

        [Test]
        public void GetEmailByCustomerNumber_TautologyInjection_DoesNotReturnEmail()
        {
            // Classic always-true tautology injection.
            // Without parameterization the injected query would be:
            //   SELECT email FROM CustomerLogin WHERE customerNumber = 1 OR 1=1
            // which returns the first row regardless of the customer number.
            // With parameterization the entire string is a data value; SQLite
            // will try to cast it to an integer, fail to match any row, and return null.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetEmailByCustomerNumber("1 OR 1=1");

            Assert.IsTrue(result == null || result == string.Empty,
                "Tautology injection payload must not retrieve any row; " +
                "parameterized query treats the value as a literal string.");
        }

        [Test]
        public void GetEmailByCustomerNumber_UnionBasedInjection_DoesNotReturnEmail()
        {
            // UNION SELECT injection.
            // Without parameterization this would append an attacker-chosen row:
            //   SELECT email FROM CustomerLogin WHERE customerNumber = 0
            //   UNION SELECT 'injected@attacker.com'
            // With parameterization the whole string is a literal value; no
            // customerNumber column equals that string, so null is returned.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetEmailByCustomerNumber(
                "0 UNION SELECT 'injected@attacker.com' --");

            Assert.IsTrue(result == null || result == string.Empty,
                "UNION-based injection payload must not retrieve any row.");
        }

        [Test]
        public void GetEmailByCustomerNumber_CommentTerminatorInjection_DoesNotReturnEmail()
        {
            // Comment-terminator payload.
            // Without parameterization:
            //   WHERE customerNumber = 100 --
            // would discard any trailing predicate and return alice's row.
            // With parameterization the stored customerNumber (integer 100) is
            // NOT equal to the literal string '100 --', so null is returned.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetEmailByCustomerNumber("100 --");

            Assert.IsTrue(result == null || result == string.Empty,
                "Comment-terminator injection must not match the stored customer number.");
        }

        [Test]
        public void GetEmailByCustomerNumber_BlindBooleanInjection_DoesNotReturnEmail()
        {
            // Blind boolean injection via AND.
            // Without parameterization:
            //   WHERE customerNumber = 100 AND 1=1
            // would still match alice's row.  With parameterization the
            // literal string '100 AND 1=1' matches no stored integer, so null
            // is returned.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetEmailByCustomerNumber("100 AND 1=1");

            Assert.IsTrue(result == null || result == string.Empty,
                "Blind boolean injection payload must not match any stored customer number.");
        }

        [Test]
        public void GetEmailByCustomerNumber_DropTableInjection_DatabaseIntact()
        {
            // Destructive stacked-query injection.
            // A naive concatenation on some drivers could execute:
            //   SELECT email FROM CustomerLogin WHERE customerNumber = 0;
            //   DROP TABLE CustomerLogin; --
            // With parameterization the table must remain intact afterwards.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetEmailByCustomerNumber(
                "0; DROP TABLE CustomerLogin; --");

            Assert.IsTrue(result == null || result == string.Empty,
                "Stacked DROP TABLE injection must not affect the database.");

            // Confirm the table still exists by doing a legitimate lookup
            string legitimateResult = provider.GetEmailByCustomerNumber("100");
            Assert.AreEqual("alice@example.com", legitimateResult,
                "CustomerLogin table must still be intact after the injection attempt.");
        }

        [Test]
        public void GetEmailByCustomerNumber_EmptyString_ReturnsNullOrEmpty()
        {
            // An empty string is a valid (if unusual) parameter value; the
            // parameterized query must handle it without throwing and return
            // null since no row has an empty customer number.
            SqliteDbProvider provider = CreateProvider();
            string result = provider.GetEmailByCustomerNumber(string.Empty);

            Assert.IsTrue(result == null || result == string.Empty,
                "Empty customer number must return null or empty, not throw.");
        }
    }
}
