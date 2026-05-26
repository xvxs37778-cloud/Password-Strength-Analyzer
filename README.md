🔐 Password Strength Analyzer
A command-line tool that analyzes password security using entropy calculation, pattern detection, and real-world attack simulations.
Built with Python — no external libraries required.

🚀 Features

Strength Score — rates password from 0 to 100
Shannon Entropy — measures true randomness of the password
Crack Time Estimate — simulates offline brute-force attack (1 billion guesses/sec)
Common Password Detection — flags passwords from top leaked lists
Pattern Detection — catches keyboard patterns (qwerty, 1234...) and repeated characters
Character Checklist — checks for lowercase, uppercase, numbers, and special characters
Actionable Tips — gives specific suggestions to improve weak passwords


📸 Demo
  Enter password: hello123

  ══════════════════════════════════════════════════════
    PASSWORD STRENGTH ANALYZER  —  by Abdullah Almutairi
  ══════════════════════════════════════════════════════

    Strength : WEAK
    [████░░░░░░░░░░░░░░░░] 20/100

    Details
      • Length     : 8 characters
      • Entropy    : 47.63 bits
      • Est. crack : 3.2 days

    Checklist
      ✔  Lowercase letters
      ✘  Uppercase letters
      ✔  Numbers
      ✘  Special characters
      ✘  Length ≥ 12
      ✘  No common patterns

    💡  Suggestions
      • Add uppercase letters (A–Z)
      • Add special characters (!@#$...)
      • Consider using 12+ characters for better security

🛠️ How to Run
bash# Clone the repository
git clone https://github.com/xvxs37778-cloud/password-analyzer.git

# Navigate to the folder
cd password-analyzer

# Run the tool
python password_analyzer.py

No pip installs needed — uses Python standard library only.


🧠 How It Works
CheckDescriptionLengthScores based on character countCharacter VarietyChecks for 4 character typesEntropyCalculates bits of randomness using Shannon formulaCommon PasswordsMatches against top leaked passwordsKeyboard PatternsDetects sequences like qwerty, 12345Repeated CharsFlags patterns like aaa, 111Crack TimeEstimates time at 1 billion guesses/second

📁 Project Structure
password-analyzer/
│
├── password_analyzer.py   # Main script
└── README.md              # Project documentation

👨‍💻 Author
Abdullah Abdulaziz Almutairi
📧 abdullah.bin.az57@gmail.com
🔗 LinkedIn : https://www.linkedin.com/in/abdullah-alshalahi-442148332?utm_source=share_via&utm_content=profile&utm_medium=member_ios
🐙 GitHub
