# Ticketing Functionality

This README documents the ticketing functionality within the SOAR platform, focusing on the integration with Jira and ServiceNow systems. It also outlines recommended changes to ensure parity between these implementations.

## Current Architecture

The ticketing functionality is split across two main components:

1. **Open Ticket** (`open_ticket/app.py`): Creates tickets in the selected ticketing system
2. **Close Ticket** (`close_ticket/app.py`): Closes tickets in the selected ticketing system

The system supports two ticketing platforms:
- **Jira**: Uses the Jira API to create and manage issues
- **ServiceNow**: Uses the ServiceNow REST API to create and manage incidents

## Current Implementation Differences

### Ticket Creation
- **Jira**
  - Creates issues with project, type, summary, description, and priority
  - Validates project existence and falls back to default
  - Uses detailed priority mapping from severity
  - Transitions tickets to initial states
  - Adds comments for ticket history

- **ServiceNow**
  - Creates incidents with predefined fields
  - Uses impact/urgency instead of direct priority mapping
  - Lacks project/queue validation
  - No post-creation state transition
  - No comment functionality

### SOC Functionality
- **Jira**
  - Routes SOC tickets to dedicated project
  - Same creation process for all tickets
  - No special priority treatment

- **ServiceNow**
  - Routes SOC tickets to specific assignment group
  - Uses different priority settings for SOC tickets
  - SOC tickets can receive higher priority than team tickets

### Ticket Closing
- **Jira**
  - Transitions tickets to final state
  - Adds closing comment
  - Falls back to deletion if transition fails

- **ServiceNow**
  - Updates state field directly
  - No comment functionality
  - No fallback mechanism

## Recommended Changes for Parity

### 1. Track Both Team and SOC Tickets

**Why**: When tickets are created for both team and SOC, both need to be tracked and closed properly.

**Implementation**:
- Modify `open_ticket/app.py` to return both ticket IDs when a SOC ticket is created
- Update data structure to include `SocTicketId` field

```python
# Return structure when both tickets are created
return {
    "TicketOpen": "Yes",
    "TicketId": ticket_id,
    "SocTicketId": soc_ticket_id
}
```

### 2. Close Both Team and SOC Tickets

**Why**: If a SOC ticket was created alongside a team ticket, both need to be closed when resolved.

**Implementation**:
- Modify `close_ticket/app.py` to check for and close SOC tickets
- Use the same closing logic for both ticket types

```python
# Check for and close SOC ticket
if 'SocTicketId' in data and data['SocTicketId']:
    soc_data = data.copy()
    soc_data['TicketId'] = data['SocTicketId']
    
    if TICKETING_SYSTEM == 'JIRA':
        use_jira(soc_data)
    elif TICKETING_SYSTEM == 'ServiceNow':
        use_service_now(soc_data)
```

### 3. ServiceNow Assignment Group Validation

**Why**: Like Jira's project validation, ServiceNow should validate assignment groups and fall back to defaults.

**Implementation**:
- Add helper function to validate ServiceNow assignment groups
- Fall back to default queue if group doesn't exist

```python
def servicenow_assignment_group_exists(group_id):
    # Implementation to check if assignment group exists
    pass
```

### 4. Consistent Documentation for Severity Translation

**Why**: While ServiceNow uses a different priority model (impact/urgency), the mapping principles should be clearly documented.

**Implementation**:
- Add detailed comments explaining the mapping logic
- Standardize the approach to ensure consistent behavior

```python
# Severity to impact/urgency mapping for ServiceNow:
# SOC tickets: impact=2 (Moderate)
# Team tickets: impact=3 (Minor)
# Urgency maps directly from severity level
```

### 5. Add Comment Functionality to ServiceNow

**Why**: Comments provide an audit trail of automated actions, important for operational transparency.

**Implementation**:
- Add work notes to ServiceNow tickets upon creation and closure
- Ensure consistent messaging between platforms

## Testing Considerations

When implementing these changes, test the following scenarios:

1. Regular team ticket creation and closure
2. SOC-only ticket creation and closure
3. Combined team+SOC ticket creation and closure
4. Edge cases like non-existent projects/groups
5. Various severity levels to ensure priority mapping works as expected

## Configuration Parameters

Both implementations use several environment variables defined in `template.yaml`:

- Common: `TICKETING_SYSTEM`, `SOC_JIRA_PROJECT_KEY_OR_SERVICE_NOW_QUEUE`, `INCIDENTS_TO_SOC`
- Jira-specific: `JIRA_*` parameters
- ServiceNow-specific: `SERVICE_NOW_*` parameters

Ensure these are consistently configured across environments.

## Future Considerations

1. Consider implementing a more abstract ticketing interface to further isolate platform-specific implementations
2. Add metrics collection for ticketing operations
3. Implement comprehensive error handling with retry logic
4. Consider adding ticket update functionality in addition to create/close operations