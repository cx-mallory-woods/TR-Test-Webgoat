using System;
using System.Text;

namespace OWASP.WebGoat.NET.Content
{
    public partial class Unsafe : System.Web.UI.Page
    {
        public void Page_Load(object sender, EventArgs args)
        {
        }

        public void btnReverse_Click(object sender, EventArgs args)
        {
            // Fix for CWE-120 (Buffer Overflow): the original implementation used an
            // unsafe block with raw pointer arithmetic and a fixed-size 256-char buffer,
            // with no bounds check on txtBoxMsg.Text.Length.  Input longer than 256
            // characters would write past the end of the buffer.
            //
            // Remediation: replace the entire unsafe pointer-based reversal with a
            // managed, bounds-safe equivalent using char[] and new string().
            // This eliminates the unsafe sink entirely so no overflow is possible.
            char[] chars = txtBoxMsg.Text.ToCharArray();
            Array.Reverse(chars);
            lblReverse.Text = new string(chars);
        }
    }
}

