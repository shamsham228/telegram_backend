FAILED_REQUESTS = {}

MAX_FAILS = 10

def record_failure(ip):

    FAILED_REQUESTS[ip] = (

        FAILED_REQUESTS.get(
            ip,
            0
        ) + 1
    )

def clear_failures(ip):

    if ip in FAILED_REQUESTS:

        del FAILED_REQUESTS[ip]

def is_blocked(ip):

    return FAILED_REQUESTS.get(
        ip,
        0
    ) >= MAX_FAILS
