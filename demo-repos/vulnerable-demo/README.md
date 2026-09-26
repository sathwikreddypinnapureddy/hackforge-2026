# Vulnerable demo

A controlled fixture with two fake, nonfunctional credentials, one tracked
environment file, and no .gitignore. Normal source files are included so the
scanner must distinguish safe code from findings.

Expected result: four findings (one critical, two high, one medium), score 37.

Do not use these values with any service. They are detection test strings only.
