# Password Tester

A simple Python password strength evaluator and strong password generator.

## Features

- Evaluate passwords for length, uppercase, lowercase, digits, and special characters
- Detect common weak patterns like `password`, `1234`, `qwerty`, and other simple sequences
- Generate strong passwords with guaranteed character category coverage
- Interactive mode for repeated evaluation and generation

## Usage

### Evaluate a password

```bash
python password-tester -e "Str0ngPassw0rd!"
```

### Generate a strong password

```bash
python password-tester -g
```

### Generate a strong password with a custom length

```bash
python password-tester -g -l 20
```

### Run interactive mode

```bash
python password-tester -i
```

### Run tests

```bash
python test_password_tester.py
```

## Notes

- The generator enforces at least one uppercase letter, one lowercase letter, one digit, and one special character.
- Password strength is rated as `Strong`, `Moderate`, or `Weak` with actionable feedback.
