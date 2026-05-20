ACTIVE_SESSIONS = {}

def register_session(

    user_id,

    session_id
):

    ACTIVE_SESSIONS[
        user_id
    ] = session_id

def validate_session(

    user_id,

    session_id
):

    return ACTIVE_SESSIONS.get(
        user_id
    ) == session_id

def revoke_session(

    user_id
):

    if user_id in ACTIVE_SESSIONS:

        del ACTIVE_SESSIONS[
            user_id
        ]
