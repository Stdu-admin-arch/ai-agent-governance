package agent.authz

default allow = false

# Rule 1: Allow low-risk, standard read-only tools unconditionally
allow if {
    input.tool == "read_public_logs"
}

# Rule 2: Allow sensitive tools only if the user tier is admin and no prompt injection is detected
allow if {
    input.tool == "execute_database_query"
    input.context.user_tier == "admin"
    input.context.prompt_injection_detected == false
}

# Rule 3: Allow standard communication tools if intent is verified and no injection exists
allow if {
    input.tool == "send_notification_email"
    input.context.intent_verified == true
    input.context.prompt_injection_detected == false
}
