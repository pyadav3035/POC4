### Feedback API Documentation
## Endpoint
# Base URL:
http://localhost:8000/api/feedback/

# Methods
# 1. Submit Feedback

**Method: POST**
**URL: /api/feedback/**
**Content-Type: application/json**
**Authentication: Not required**
**Request Body Example**

### Request Body Example
{
  "module": "Login",
  "userlogin": 12345,
  "remarks": "Very user-friendly module.",
  "is_active": 1,
  "username": "john.doe",
  "personal_no": "PN123456",
  "phone_no": "+919876543210",
  "nudid": "NUD12345",
  "question1": "5",
  "question2": "4",
  "question3": "5",
  "question4": "4"
}

**insert_datetime, modified_datetime, and avg_feedback are set automatically.**

### Success Response Example
{
  "id": 1,
  "module": "Login",
  "userlogin": 12345,
  "remarks": "Very user-friendly module.",
  "insert_datetime": "2025-08-17T14:23:45.123Z",
  "modified_datetime": "2025-08-17T14:23:45.123Z",
  "is_active": 1,
  "username": "john.doe",
  "personal_no": "PN123456",
  "phone_no": "+919876543210",
  "nudid": "NUD12345",
  "question1": "5",
  "question2": "4",
  "question3": "5",
  "question4": "4",
  "avg_feedback": "4.5"
}

### Error Response Example

{
  "question1": ["This field is required."],
  "is_active": ["This field is required."]
}


### 2. Get All Feedbacks

Method: GET
URL: /api/feedback/
Authentication: Not required
# Success Response Example
[
  {
    "id": 1,
    "module": "Login",
    "userlogin": 12345,
    "remarks": "Very user-friendly module.",
    "insert_datetime": "2025-08-17T14:23:45.123Z",
    "modified_datetime": "2025-08-17T14:23:45.123Z",
    "is_active": 1,
    "username": "john.doe",
    "personal_no": "PN123456",
    "phone_no": "+919876543210",
    "nudid": "NUD12345",
    "question1": "5",
    "question2": "4",
    "question3": "5",
    "question4": "4",
    "avg_feedback": "4.5"
  },
  ...
]

***Notes***
# Average Feedback Calculation:
*The backend automatically calculates avg_feedback as the average of question1 to question4 (each rated 1–5).*

# Date Fields:
*insert_datetime and modified_datetime are set by the backend.*

# Required Fields:
*All fields except remarks, personal_no, phone_no, and nudid are required.*



