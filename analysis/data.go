package analysis

var VulnerabilityPatterns = map[string]string{
	"eval":                "'eval' in JavaScript can lead to remote code execution. Avoid its usage by using safer alternatives.",
	"exec":                "'exec' in Node.js can allow command injection. Use child_process.execFile or parameterized inputs.",
	"os.system":           "'os.system' calls in Python are prone to command injection. Always validate inputs.",
	"dangerous_file":      "PHP file handling vulnerabilities can expose sensitive files. Ensure proper sanitization of file paths.",
	"document.write":      "'document.write' in JavaScript can lead to XSS vulnerabilities. Use DOM manipulation APIs instead.",
	"innerHTML":           "Direct assignment to 'innerHTML' can cause DOM-based XSS attacks. Use textContent instead.",
	"shell_exec":          "PHP 'shell_exec' is prone to command injection. Avoid or use escapeshellcmd/escapeshellarg.",
	"document.location":   "'document.location' manipulation can redirect to malicious sites. Always sanitize inputs.",
}

var CWEDetails = map[string]struct {
	Description string
	CWEID       string
}{
	"eval":                {"Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')", "CWE-95"},
	"exec":                {"Improper Neutralization of Special Elements used in a Command ('Command Injection')", "CWE-77"},
	"os.system":           {"Improper Neutralization of Special Elements used in a Command ('Command Injection')", "CWE-78"},
	"dangerous_file":      {"Improper Restriction of Operations within the Bounds of a Memory Buffer", "CWE-119"},
	"document.write":      {"Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting')", "CWE-79"},
	"innerHTML":           {"Improper Neutralization of Script-Related HTML Tags in a Web Page", "CWE-80"},
	"shell_exec":          {"Improper Neutralization of Special Elements used in a Command ('Command Injection')", "CWE-78"},
	"document.location":   {"Improper Input Validation", "CWE-20"},
}

