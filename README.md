# **Backend API Documentation**

**Base URL:** http://127.0.0.1:5000

---

## **Authentication**

### **Register**

- **POST** /register
- **Request Body (JSON):**

```
{
  "username": "your_username",
  "password": "your_password"
}
```

- 
- **Response:**
    - 201 Created on success
    - 400 if fields missing
    - 409 if username exists

---

### **Login**

- **POST** /login
- **Request Body (JSON):**

```
{
  "username": "your_username",
  "password": "your_password"
}
```

- 
- **Response:**

```
{
  "access_token": "JWT_TOKEN"
}
```

- 
- Use the returned token in future requests:

```
Authorization: Bearer JWT_TOKEN
```

---

## **Jobs**

All /sync_jobs, /upload_file, and /download_file endpoints require a **valid JWT token**.

---

### **Sync Jobs**

- **POST** /sync_jobs
- Replaces current user jobs:
    - Adds new jobs
    - Updates changed ones
    - Deletes jobs not in the list
- **Request Headers:**

```
Authorization: Bearer JWT_TOKEN
```

- 
- **Request Body (JSON):**

```
[
  {
    "file_name": "example.gcode",
    "file_path": "/user/jobs/example.gcode",
    "priority": 1
  },
  ...
]
```

- 
- **Response:**

```
{
  "message": "Jobs synced successfully",
  "added": 1,
  "deleted": 0,
  "kept": 1,
  "updated": 1
}
```

---

### **Get Jobs**

- **GET** /sync_jobs
- **Headers:**

```
Authorization: Bearer JWT_TOKEN
```

- 
- **Response:**

```
[
  {
    "id": 1,
    "file_name": "example.gcode",
    "file_path": "/user/jobs/example.gcode",
    "priority": 1,
    "file_exist": true
  }
]
```

---

### **Upload File to Job**

- **PUT** /upload_file/<job_id>
- Uploads binary file data to an existing job
- **Headers:**

```
Authorization: Bearer JWT_TOKEN
Content-Type: multipart/form-data
```

- 
- **Form Field:** file (binary file)
- **Response:**

```
{
  "message": "File uploaded successfully"
}
```

---

### **Download File from Job**

- **GET** /download_file/<job_id>
- Downloads the binary file from a job
- **Headers:**

```
Authorization: Bearer JWT_TOKEN
```

- 
- **Response:** File as attachment (with original file name)

---

## **Notes**

- file_path is used as a unique identifier per user.
- Job changes are automatically detected and synced on /sync_jobs.
- JWT token is required for all operations except register/login.

---
