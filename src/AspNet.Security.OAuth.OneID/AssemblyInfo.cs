using System;
using System.Runtime.InteropServices;

[assembly: CLSCompliant(false)]	// Can't be CLS colpiant (supported by other .NET language) as many of the oAuth types are not CLS compliant
[assembly: ComVisible(false)]   // No need in COM exposure (it's true by default)