import json
import os


ALLOWED_PAYMENT_PROVIDERS = {"OPay", "PalmPay", "Moniepoint"}


def load_payment_accounts():
    raw = os.environ.get("NOVA_PAYMENT_ACCOUNTS_JSON", "").strip()

    if not raw:
        if os.environ.get("FLASK_ENV", "").lower() == "production":
            raise RuntimeError(
                "NOVA_PAYMENT_ACCOUNTS_JSON must be configured in production"
            )
        return []

    try:
        accounts = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("NOVA_PAYMENT_ACCOUNTS_JSON must contain valid JSON") from exc

    if not isinstance(accounts, list) or not accounts:
        raise RuntimeError("NOVA_PAYMENT_ACCOUNTS_JSON must be a non-empty JSON array")

    validated = []
    seen_providers = set()

    for account in accounts:
        if not isinstance(account, dict):
            raise RuntimeError("Each payment account must be a JSON object")

        provider = str(account.get("provider", "")).strip()
        account_number = str(account.get("account_number", "")).strip()

        if provider not in ALLOWED_PAYMENT_PROVIDERS:
            raise RuntimeError(f"Unsupported payment provider: {provider}")
        if provider in seen_providers:
            raise RuntimeError(f"Duplicate payment provider: {provider}")
        if not account_number or not account_number.isdigit():
            raise RuntimeError(f"Invalid account number for {provider}")

        seen_providers.add(provider)
        validated.append(
            {
                "provider": provider,
                "account_number": account_number,
            }
        )

    return validated


PAYMENT_ACCOUNTS = load_payment_accounts()
