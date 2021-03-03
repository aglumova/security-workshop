# Task

The application is hosted in `<URL>`.

admin is:
- username: admin
- password: test

user is:
- username: user
- password: password

---
1. Choose one of the Threat Modeling Methodology
2. Find all possible vulnerabilities
3. Estimate the risks
4. Describe solutions for found vulnerabilities
5. Prepare fix plan

# Result

**NOTE:** Create private github repository and share it with me.

1. Note selected Threat Modeling Methodology in the `README.md` file.
2. Describe which vulnerabilities you found in the `README.md` file and where.

**Example:**

- Vulnerability: XSS
- Where: Address input in the registration page
- How to reproduce: Insert <script>alert(1);</script>

3. Estimate the risks based on the selected methodology or a custom estimation for each vulnerability
4. Describe how to fix each vulnerability in scope of your language (library, framework, etc).
5. Provide code snippet where you are using one of the provided solution in the code (any test or working code example).

# Score

- _Result section 1 point:_ +5.

- _Result section 2 point:_ +10 for each valid **full** description.

NOTE: You should explain where are you find vulnerability and how to reproduce the problem.

- _Result section 3 point:_ +10 for estimations based in impact.

- _Result section 4 point:_ +10 for each valid **full** description.

- _Result section 5 point:_ +30 for each valid **correct** solution.


**NOTE:** Score is 0 in case section is not describing fully.

# How to know score and possible incorrectness?

I will create PR (pull request) to your repository with feedback in `.md` file. 
The future discussion and fixes we can discuss in the PR.
