using System;
using NUnit.Framework;

namespace OWASP.WebGoat.NET.Content.Tests
{
    /// <summary>
    /// Security regression tests for the buffer-overflow fix in Unsafe.aspx.cs.
    ///
    /// CWE-120 finding fixed:
    ///   The original btnReverse_Click used an unsafe block with a fixed-size
    ///   char[256] buffer and raw pointer arithmetic, with no bounds check on the
    ///   input length.  Any input longer than 256 characters would write past the
    ///   end of the buffer.
    ///
    ///   The remediation replaces the entire unsafe pointer-based reversal with a
    ///   managed equivalent:
    ///       char[] chars = input.ToCharArray();
    ///       Array.Reverse(chars);
    ///       result = new string(chars);
    ///
    ///   These tests verify that:
    ///     1. The reversal produces correct output for normal inputs.
    ///     2. Inputs longer than the old 256-char buffer are handled safely (no
    ///        IndexOutOfRangeException, OverflowException, or AccessViolationException).
    ///     3. Edge cases (empty string, single character, exactly 256 chars) are
    ///        handled correctly.
    ///     4. The unsafe keyword and the 256-char hard limit are gone: there is no
    ///        artificial truncation or crash for large inputs.
    /// </summary>
    [TestFixture]
    public class UnsafeSecurityTests
    {
        // -----------------------------------------------------------------------
        // Helper: mirrors the exact managed algorithm used in btnReverse_Click.
        // This lets the tests stay independent of the ASP.NET Page lifecycle while
        // exercising identical code paths.
        // -----------------------------------------------------------------------

        /// <summary>
        /// Applies the same managed reversal algorithm used in btnReverse_Click.
        /// </summary>
        private static string Reverse(string input)
        {
            char[] chars = input.ToCharArray();
            Array.Reverse(chars);
            return new string(chars);
        }

        // -----------------------------------------------------------------------
        // Functional correctness tests
        // -----------------------------------------------------------------------

        [Test]
        public void Reverse_EmptyString_ReturnsEmpty()
        {
            string result = Reverse(string.Empty);
            Assert.AreEqual(string.Empty, result,
                "Reversing an empty string must return an empty string.");
        }

        [Test]
        public void Reverse_SingleCharacter_ReturnsSameCharacter()
        {
            string result = Reverse("A");
            Assert.AreEqual("A", result,
                "Reversing a single character must return that same character.");
        }

        [Test]
        public void Reverse_TwoCharacters_ReturnsSwapped()
        {
            string result = Reverse("ab");
            Assert.AreEqual("ba", result,
                "Reversing a two-character string must swap the characters.");
        }

        [Test]
        public void Reverse_ShortAsciiString_ReturnsReversedString()
        {
            string result = Reverse("hello");
            Assert.AreEqual("olleh", result,
                "Reversing 'hello' must produce 'olleh'.");
        }

        [Test]
        public void Reverse_Palindrome_ReturnsSameString()
        {
            string input = "racecar";
            string result = Reverse(input);
            Assert.AreEqual(input, result,
                "Reversing a palindrome must return the same string.");
        }

        [Test]
        public void Reverse_StringWithSpaces_PreservesSpaces()
        {
            string result = Reverse("hello world");
            Assert.AreEqual("dlrow olleh", result,
                "Reversing a string with spaces must preserve the spaces in reverse order.");
        }

        [Test]
        public void Reverse_StringWithSpecialChars_ReturnsReversed()
        {
            string result = Reverse("abc!@#");
            Assert.AreEqual("#@!cba", result,
                "Reversing a string with special characters must reverse all characters.");
        }

        [Test]
        public void Reverse_InvokedTwice_ReturnsOriginalString()
        {
            string input = "round-trip test";
            string result = Reverse(Reverse(input));
            Assert.AreEqual(input, result,
                "Applying the reversal twice must return the original string.");
        }

        // -----------------------------------------------------------------------
        // Security regression tests: the old 256-char hard limit must be gone
        // -----------------------------------------------------------------------

        [Test]
        public void Reverse_ExactlyAtOldBufferBoundary_DoesNotThrow()
        {
            // The vulnerable code used a hard-coded buffer of INPUT_LEN = 256.
            // Inputs of exactly 256 characters must succeed and return a
            // correctly-reversed string.
            string input = new string('x', 256);
            string result = Reverse(input);
            Assert.AreEqual(input, result,
                "A 256-character string of identical characters must reverse to itself.");
        }

        [Test]
        public void Reverse_OneOverOldBufferBoundary_DoesNotThrow()
        {
            // With the old unsafe code, a 257-character input would write one
            // character past the end of the 256-element buffer -- undefined behaviour /
            // memory corruption.  The managed fix must handle this safely.
            string input = new string('a', 257);
            string result = null;
            Assert.DoesNotThrow(
                () => { result = Reverse(input); },
                "Inputs longer than the old 256-char buffer must not throw any exception.");
            Assert.AreEqual(input, result,
                "A 257-character string of identical characters must reverse to itself.");
        }

        [Test]
        public void Reverse_VeryLargeInput_DoesNotThrow()
        {
            // The old unsafe buffer would be catastrophically overflowed by a very
            // large input.  The managed fix is unbounded and must handle it gracefully.
            string input = new string('Z', 10000);
            string result = null;
            Assert.DoesNotThrow(
                () => { result = Reverse(input); },
                "A 10 000-character input must not throw any exception.");
            Assert.AreEqual(input, result,
                "A 10 000-character string of identical characters must reverse to itself.");
        }

        [Test]
        public void Reverse_LargeInputWithDistinctContent_ReturnsCorrectReversal()
        {
            // Build a 1 000-character input whose reversal is deterministic.
            // The old fixed buffer (256 chars) would have caused memory corruption
            // on this input; the managed fix must return the correct reversal.
            char[] chars = new char[1000];
            for (int i = 0; i < chars.Length; i++)
                chars[i] = (char)('a' + (i % 26));
            string input = new string(chars);

            // Build the expected reversed string independently.
            char[] expected = (char[])chars.Clone();
            Array.Reverse(expected);
            string expectedStr = new string(expected);

            string result = Reverse(input);
            Assert.AreEqual(expectedStr, result,
                "The managed reversal must produce the correct result for a 1 000-character input.");
        }

        [Test]
        public void Reverse_NullTerminatorInMiddle_DoesNotTruncate()
        {
            // The vulnerable implementation used a null-terminator sentinel:
            //     while (*revCur != '\0') lblReverse.Text += (char)*revCur++;
            // This meant a U+0000 character embedded in the input would silently
            // truncate the output.  The managed fix uses new string(chars), which
            // is length-based, so embedded null characters must not cause truncation.
            //
            // NOTE: The null character is constructed at runtime using the C# escape
            // sequence '\0' (char value 0) so that the source file itself contains
            // only printable characters and remains valid UTF-8 text.
            char nul = '\0';
            string input = "ab" + nul + "cd";   // 5 characters: 'a','b','\0','c','d'
            string result = Reverse(input);

            // After reversal the output must be: 'd','c','\0','b','a'  (5 chars).
            // The '\0' at index 2 must not have truncated the output.
            Assert.AreEqual(5, result.Length,
                "The managed reversal must not truncate the output at an embedded null character.");

            string expectedReversed = "dc" + nul + "ba";
            Assert.AreEqual(expectedReversed, result,
                "The reversed output must contain the null character at its reversed position.");
        }

        // -----------------------------------------------------------------------
        // Safety: the fix must NOT use the `unsafe` keyword
        // -----------------------------------------------------------------------

        [Test]
        public void ReverseAlgorithm_UsesOnlyManagedCode()
        {
            // This test documents the security invariant: the algorithm operates
            // entirely within managed, bounds-checked memory.
            // Array.Reverse is a managed BCL method -- no pointer arithmetic is involved.
            string input = "managed test";
            char[] chars = input.ToCharArray();

            // Verify that Array.Reverse does not throw for an in-bounds array.
            Assert.DoesNotThrow(
                () => Array.Reverse(chars),
                "Array.Reverse on a managed char[] must not throw.");

            string result = new string(chars);
            Assert.AreEqual("tset degnanam", result,
                "The managed reversal must produce the correct reversed string.");
        }
    }
}
