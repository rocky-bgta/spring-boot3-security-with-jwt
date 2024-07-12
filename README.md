# spring-security

Simple json payload to create user:
{
"username": "tuli",
"password": "tuli",
"roleList": [
{
"roleName":"ROLE_USER"
}

]
}

# curl for refresh token:
curl --location 'http://localhost:8080/refreshtoken' \
--header 'isRefreshToken: true' \
--header 'Authorization: ••••••' \


curl -X GET "http://localhost:8080/refreshtoken" \
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huZG9lIiwiaWF0IjoxNjE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" \
-H "isRefreshToken: true"