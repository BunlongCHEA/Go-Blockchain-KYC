# I. Project Structure & Key Features

- **Project Structure**

```bash
Go-Blockchain-KYC/
├── main.go                    # Application entry point
├── go.mod                     # Go module file
├── config.json               # Configuration file
├── Dockerfile                 # Docker build file
├── docker-compose.yml        # Docker Compose file
│
├── config/
│   └── config.go              # Configuration management
├── crypto/
│   ├── keys.go                # Key pair generation (RSA/ECDSA)
│   ├── signing.go             # Digital signature operations
│   └── encryption.go          # Data encryption (AES-256)
├── auth/
│   ├── auth.go                # Authentication
│   ├── jwt.go                 # JWT token management
│   └── rbac.go                # Role-based access control
├── models/
│   ├── block.go               # Block structure
│   ├── blockchain.go          # Blockchain logic
│   ├── kyc.go                 # KYC data structures
│   ├── transaction.go         # Transaction handling
│   └── bank.go                # Bank entity
├── consensus/
│   ├── consensus.go           # Consensus interface
│   ├── pbft.go                # PBFT implementation
│   └── raft.go                # Raft implementation
├── storage/
│   ├── storage.go             # Storage interface
│   ├── postgres.go            # PostgreSQL implementation
│   └── migrations.go          # Database migrations
├── api/
│   ├── server.go              # HTTP server
│   ├── routes.go              # API routes
│   ├── handlers.go            # Request handlers
│   ├── middleware.go          # Middleware (auth, logging)
│   └── responses.go           # Response helpers
|__ utils/
    └── utils.go               # Utility functions
```

- **Key Features**

| Feature | Description |
|---|---|
| `CRUD Operations` | Create, Read, Update, Delete KYC records |
| `Immutable Ledger` | All transactions are permanently recorded |
| `Bank Authorization` | Only registered banks can perform operations |
| `KYC Verification` | Banks can verify/reject customer KYC |
| `Transaction History` | Complete audit trail per customer |
| `Chain Validation` | Integrity checking of the blockchain |
| `Risk Assessment` | Basic risk level calculation |
| `Document Hashing` | Store document verification hashes |

# II. How to Use
## 1. Run Go Project: Either Localhost or Production Run (Docker, Kubernetes)

Initialize Go module and download dependencies
```bash
go mod init Go-Blockchain-KYC
go mod tidy
```

Or run locally, but need to start PostgreSQL First
Then run:
```bash
go run .
```

You will see this TUI:
![Terminal Go Run - Success Start Localhost Server](/images/bash-1.png)


## 2. Postman: To Work and Verify
### Create Environments & Collections

Open Postman and Create:

- Environments
![POSTMAN - Create Environment](/images/postman-1.png)

- Collections: create any name and **Add request by find this symbol +** 
![POSTMAN - Create Collections with **Add request**](/images/postman-2.png)


### Configure the Request to Verify Server Access

Set Request

| Setting | Value |
|---|---|
| `Method` | POST |
| `URL` | http://localhost:8080/api/v1/auth/login |

Set Header

- Click on "Headers" tab
- Add the following header:

| Key | Value |
|---|---|
| `Content-Type` | application/json |

Set Request Body

- Click on "Body" tab
- Select "raw"
- Choose "JSON" from the dropdown (right side)
- Enter the JSON:

```json
{
    "username": "admin",
    "password": "admin123"
}
```

Send Request

- Click the "Send" button (blue button)
- You should receive a response like this:

```json
{
    "success": true,
    "message":  "login successful",
    "data": {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.. .",
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "expires_at": "2026-01-02T21:17:52Z",
        "user": {
            "id": "USR.. .",
            "username": "admin",
            "email": "admin@kyc-blockchain.com",
            "role": "admin"
        }
    }
}
```


### Create A New Bank & KYC
#### Create Bank

Login Username as Admin (Not Bank Admin): To get token

- Pass this script below to **Scripts**, so that it create Environment Variable:
    - access_token
    - refresh_token

```bash
// Set global variable - token - and call on Headers as Authorization Bearer
var response = pm.response.json();

var accessToken = response.data.access_token;
var refreshToken = response.data.refresh_token;

// save as environment variables
pm.environment.set("access_token", accessToken);
pm.environment.set("refresh_token", refreshToken);
```

Add New Request: Set Header

- Create or Duplicate the new request
- Go to **Headers** & Add

| Key | Value |
|---|---|
| `Content-Type` | application/json |
| `Authorization` | Bearer {{access_token}} |

Set Request: Create A Bank

| Setting | Value |
|---|---|
| `Method` | POST |
| `URL` | http://localhost:8080/api/v1/banks |

Set Request Body

- Click on "Body" tab
- Select "raw"
- Choose "JSON" from the dropdown (right side)
- Enter the JSON:

```json
{
    "name": "Cambodia National Bank",
    "code": "CNB",
    "country": "Cambodia",
    "license_no": "LIC-KH-001",
    "public_key": "",
    "address": {
        "street": "123 Norodom Blvd",
        "city": "Phnom Penh",
        "state": "Phnom Penh",
        "postal_code": "12000",
        "country": "Cambodia"
    },
    "contact_email": "contact@cnb.com.kh",
    "contact_phone": "+85523456789"
}
```

- Expected Response:
![POSTMAN - Output Success Created Bank](/images/postman-3.png)

⚠️ Save the id (e.g., BANK1a2b3c4d) - you'll need it for the next step!

#### Create KYC

First, you can Duplicate Request from Request **Login Admin**

Then, you need to login as a bank user. Since admin doesn't have a bank_id, let's use bank_admin:

| Setting | Value |
|---|---|
| `Method` | POST |
| `URL` | http://localhost:8080/api/v1/auth/login |

Set Request Body (JSON)

```json
{
    "username": "bank_admin",
    "password": "bank123"
}
```

Set Header : Like above admin to the **Scripts**

-----

Set Request: Create A KYC

| Setting | Value |
|---|---|
| `Method` | POST |
| `URL` | http://localhost:8080/api/v1/kyc |

Set Header

| Key | Value |
|---|---|
| `Authorization` | Bearer {{access_token}} |

Set Request Body (JSON)

```json
{
    "first_name": "Test",
    "last_name": "Test",
    "date_of_birth": "1990-05-15",
    "nationality":  "Cambodian",
    "id_type": "national_id",
    "id_number": "KH123456789",
    "id_expiry_date": "2030-05-15",
    "address":  {
        "street": "456 Mao Tse Tong Blvd",
        "city": "Phnom Penh",
        "state": "Phnom Penh",
        "postal_code": "12000",
        "country": "Cambodia"
    },
    "email": "test.test@email.com",
    "phone":  "+85512345678"
}
```

- Expected Response:
![POSTMAN - Output Success Created KYC, but statue remain PENDING](/images/postman-4.png)

⚠️ Save the customer_id for verification!


### Verify - Is Block/Blockchain Created?
#### Check Pending Transactions

When you create a KYC, it first goes to pending transactions (not yet in a block).

Set Request

| Setting | Value |
|---|---|
| `Method` | GET |
| `URL` | http://localhost:8080/api/v1/blockchain/pending |

Set Header

| Key | Value |
|---|---|
| `Authorization` | Bearer {{access_token}} |

- Expected Response:
![POSTMAN - Output Success for verify KYC, but statue remain PENDING](/images/postman-5.png)

#### Mine a Block (Add Transactions to Blockchain)

To add pending transactions to the blockchain, you need to **mine a block**:

⚠️ **NOTE:** This time Login as Admin; Otherwise, will error insufficient permission

Set Request

| Setting | Value |
|---|---|
| `Method` | POST |
| `URL` | http://localhost:8080/api/v1/blockchain/mine |

Set Header

| Key | Value |
|---|---|
| `Authorization` | Bearer {{access_token}} |

- Expected Response:
![POSTMAN - Output Success Mining, & Created a Block to Blockchain](/images/postman-6.png)

#### Check Blockchain Stats

Set Request

| Setting | Value |
|---|---|
| `Method` | GET |
| `URL` | http://localhost:8080/api/v1/blockchain/stats |

Set Header

| Key | Value |
|---|---|
| `Authorization` | Bearer {{access_token}} |

- Expected Response:
![POSTMAN - Output Validate Success Blockchain Stats](/images/postman-7.png)

#### View All Blocks

Set Request

| Setting | Value |
|---|---|
| `Method` | GET |
| `URL` | http://localhost:8080/api/v1/blockchain/blocks |

Set Header

| Key | Value |
|---|---|
| `Authorization` | Bearer {{access_token}} |

- Expected Response:
![POSTMAN - Output View All Block in Blockchain](/images/postman-8.png)

#### Validate Blockchain Integrity

Set Request

| Setting | Value |
|---|---|
| `Method` | GET |
| `URL` | http://localhost:8080/api/v1/blockchain/validate |

Set Header

| Key | Value |
|---|---|
| `Authorization` | Bearer {{access_token}} |

- Expected Response:
![POSTMAN - Output Validate Blockchain Integrity](/images/postman-9.png)


# Summary Logic:

```bash
┌─────────────────────────────────────────────────────────────────────┐
│                        BLOCKCHAIN FLOW                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. CREATE KYC                                                      │
│     ↓                                                               │
│  ┌─────────────────────────────────────┐                           │
│  │     PENDING TRANSACTIONS            │  ← Transaction created    │
│  │     - KYC Create (CUS1a2b3c4d)      │                           │
│  └─────────────────────────────────────┘                           │
│     ↓                                                               │
│  2. MINE BLOCK                                                      │
│     ↓                                                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                     BLOCKCHAIN                               │   │
│  │                                                              │   │
│  │  ┌──────────┐      ┌──────────────────────────────────┐     │   │
│  │  │ Block 0  │ ───► │ Block 1                          │     │   │
│  │  │ (Genesis)│      │ - TX: KYC Create (CUS1a2b3c4d)   │     │   │
│  │  │ Hash: 000a│      │ - PrevHash: 000a                 │     │   │
│  │  └──────────┘      │ - Hash: 000e                     │     │   │
│  │                    └──────────────────────────────────┘     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```