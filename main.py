from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes
)

BOT_TOKEN = "YOUR_BOT_TOKEN"

registered_users = {}

async def start(

    update: Update,

    context: ContextTypes.DEFAULT_TYPE
):

    user = update.effective_user

    username = user.username

    telegram_id = user.id

    first_name = user.first_name

    language = user.language_code

    if username:

        registered_users[
            username.lower()
        ] = telegram_id

    registered_users[
        str(telegram_id)
    ] = telegram_id

    message = f"""
✅ NetBridge Connected

Username: @{username}

ID: {telegram_id}

First: {first_name}

Lang: {language}

You can now return to the app and login securely.
"""

    await update.message.reply_text(
        message
    )

app = (
    ApplicationBuilder()
    .token(BOT_TOKEN)
    .build()
)

app.add_handler(
    CommandHandler(
        "start",
        start
    )
)

print("BOT STARTED")

app.run_polling()
