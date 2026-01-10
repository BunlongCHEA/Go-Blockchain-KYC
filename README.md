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


### Configure the Request to Verify Server Access by Login as Admin

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

Set Scripts

Pass this script below to **Scripts**, so that it create Environment Variable:
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

Before start, you must login or remain as **admin** to create bank due to permission requirement

```json
{
    "username": "admin",
    "password": "admin123"
}
```

Then you can Duplicate Request from Request **Login Admin**

Then, you need to login as a bank user. Since admin doesn't have a bank_id, let's use bank_admin:

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

Set Request Body (JSON)

```json
{
    "username": "bank_admin",
    "password": "bank123"
}
```

#### Create Bank

Add a New Request:

- Create or Duplicate the new request
- Go to **Headers** & Add

Set Request: Create A Bank

| Setting | Value |
|---|---|
| `Method` | POST |
| `URL` | http://localhost:8080/api/v1/banks |

Set Header:

| Key | Value |
|---|---|
| `Content-Type` | application/json |
| `Authorization` | Bearer {{access_token}} |

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

#### Create KYC (Status: PENDING)

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

READ KYC (Check Status) with ⚠️ saved customer_id

| Setting | Value |
|---|---|
| `Method` | GET |
| `URL` | http://localhost:8080/api/v1/kyc?customer_id=CUSa1b2c3d4e5f6 |

![POSTMAN - Output Checking KYC, but statue remain PENDING](/images/postman-4_1.png)

#### Check Pending Transactions (Should be Empty)

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
![POSTMAN - Output Success for verify KYC, but remain Empty block as KYC not Verified yet](/images/postman-5.png)

**This mean KYC cannot allow to mine yet, while remain PENDING status, it requires to VERIFY KYC First**

- Expected Response:
![POSTMAN - Output Error, KYC PENDING status, so no pending transaction to mine](/images/postman-5_4.png)

#### VERIFY KYC (Creates Transaction)

Set Request

| Setting | Value |
|---|---|
| `Method` | POST |
| `URL` | http://localhost:8080/api/v1/kyc/verify |

Set Header

| Key | Value |
|---|---|
| `Authorization` | Bearer {{access_token}} |

Set Request Body (JSON)
⚠️ Use customer_id for verification to **"VERIFIED"**

```json
{
    "customer_id": "CUSa1b2c3d4e5f6"
}
```

- Expected Response:
![POSTMAN - Output Success for verify KYC, Status VERIFIED](/images/postman-5_1.png)

![POSTGRES - Output Database verify KYC to status VERIFIED](/images/postman-5_2.png)


### Verify - Is Block/Blockchain Created?
#### Check Pending Transactions (NOW Should be Created Block)

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
![POSTMAN - Output Success to KYC data for Block](/images/postman-5_3.png)

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


# III. Summary Logic:

```bash
┌─────────────────────────────────────────────────────────────────────┐
│                 BLOCKCHAIN FLOW ( Manual Verify KYC )               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. LOGIN ──────────────────────► Get Token                         │
│                                                                     │
│  2. CREATE KYC ─────────────────► Status: PENDING                   │
│                                         Saved to:  Database Only    │
│                                         Blockchain: ❌              │
│                                                                     │
│  3. READ KYC ───────────────────► can_modify: true                  │
│                                         can_verify: true            │
│                                         on_blockchain: false        │
│                                                                     │
│  4. UPDATE KYC ─────────────────► Status: PENDING                   │
│                                         Updated in:  Database Only  │
│                                                                     │
│  5. CHECK PENDING ──────────────► Empty []                          │
│                                                                     │
│  6. VERIFY KYC ─────────────────► Status: VERIFIED                  │
│                                         Transaction Created ✅      │
│                                                                     │
│  7. CHECK PENDING ──────────────► Has Transaction                   │
│     ↓                                                               │
│  ┌─────────────────────────────────────┐                            │
│  │     PENDING TRANSACTIONS            │  ← Transaction created     │
│  │     - KYC Create (CUS1a2b3c4d)      │                            │
│  └─────────────────────────────────────┘                            │
│     ↓                                                               |
│  8. MINE BLOCK ─────────────────► Block Created ✅                  │
│                                   Added to Blockchain ✅            │
│     ↓                                                               │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                     BLOCKCHAIN                              │    │
│  │                                                             │    │
│  │  ┌──────────┐      ┌──────────────────────────────────┐     │    │
│  │  │ Block 0  │ ───► │ Block 1                          │     │    │
│  │  │ (Genesis)│      │ - TX: KYC Create (CUS1a2b3c4d)   │     │    │
│  │  │ Hash: 000a│     │ - PrevHash: 000a                 │     │    │
│  │  └──────────┘      │ - Hash: 000e                     │     │    │
│  │                    └──────────────────────────────────┘     │    │
│  └─────────────────────────────────────────────────────────────┘    │
│  9. VERIFY ─────────────────────► total_blocks: 2                   │
│                                   is_valid: true                    │
│                                                                     │
│  10.TRY UPDATE ─────────────────► FAILED ❌                         │
│                                   "already on blockchain"           │
│                                                                     │
│  11.TRY DELETE ─────────────────► FAILED ❌                         │
│                                   "already on blockchain"           │
└─────────────────────────────────────────────────────────────────────┘
```

**Otherwise, if KYC's status still PENDING, will error to mine Block to Blockchain**

```bash
┌─────────────────────────────────────────────────────────────────┐
│                    PENDING KYC                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  CREATE KYC (PENDING)                                           │
│       │                                                         │
│       ▼                                                         │
│  ┌─────────────────────┐                                        │
│  │  PostgreSQL (DB)    │  ✅ Saved here                         │
│  │  - KYC Data         │                                        │
│  │  - Status:  PENDING │                                        │
│  └─────────────────────┘                                        │
│                                                                 │
│       ❌ NO transaction created                                 │
│                                                                 │
│  ┌─────────────────────┐                                        │
│  │  Pending Pool       │  Empty []                              │
│  │  (No transactions)  │                                        │
│  └─────────────────────┘                                        │
│                                                                 │
│       │                                                         │
│       ▼  TRY MINE                                               │
│                                                                 │
│  ┌─────────────────────┐                                        │
│  │  MINE BLOCK         │  ❌ FAILED                             │
│  │  "no pending        │  "no pending transactions to mine"     │
│  │   transactions"     │                                        │
│  └─────────────────────┘                                        │
│                                                                 │
│  ┌─────────────────────┐                                        │
│  │  BLOCKCHAIN         │                                        │
│  │  ┌────────────┐     │                                        │
│  │  │ Block 0    │     │  Only genesis block                    │
│  │  │ (Genesis)  │     │  No new block added                    │
│  │  └────────────┘     │                                        │
│  └─────────────────────┘                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Comparison: PENDING vs VERIFIED**

| Status     | Saved to DB | Transaction Created | Can Mine | Goes to Blockchain |
|------------|-------------|---------------------|----------|--------------------|
| `PENDING`  | ✅ Yes      | ❌ No               | ❌ No    | ❌ No              |
| `VERIFIED` | ✅ Yes      | ✅ Yes              | ✅ Yes   | ✅ Yes             |
| `REJECTED` | ✅ Yes      | ❌ No               | ❌ No    | ❌ No              |
| `SUSPENDED`| ✅ Yes      | ❌ No               | ❌ No    | ❌ No              |

**Auto Verification KYC, with Didit Provider or other Provider**

```bash
┌─────────────────────────────────────────────────────────────────────┐
│                    DIDIT VERIFICATION FLOW                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Call /api/v1/kyc/auto-verify                                    │
│       │                                                             │
│       ▼                                                             │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  DIDIT API                                                   │   │
│  │                                                              │   │
│  │  Step 1: Authenticate (OAuth2)                               │   │
│  │       │                                                      │   │
│  │       ▼                                                      │   │
│  │  Step 2: Create Session                                      │   │
│  │       │                                                      │   │
│  │       ▼                                                      │   │
│  │  Step 3: Submit KYC Data                                     │   │
│  │       │                                                      │   │
│  │       ▼                                                      │   │
│  │  Step 4: Didit Performs Checks:                              │   │
│  │       ├── Document Verification (OCR)                        │   │
│  │       ├── Face Match                                         │   │
│  │       ├── AML/PEP/Sanctions Check                            │   │
│  │       └── Risk Scoring                                       │   │
│  │       │                                                      │   │
│  │       ▼                                                      │   │
│  │  Step 5: Return Decision                                     │   │
│  └──────────────────────────────────────────────────────────────┘   │
│       │                                                             │
│       ▼                                                             │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  AUTO-DETERMINE STATUS                                       │   │
│  │                                                              │   │
│  │  Decision: "approved"  ────► VERIFIED ───► Blockchain ✅     │   │
│  │  Decision: "declined"  ────► REJECTED ───► DB Only ❌        │   │
│  │  Decision: "review"    ────► PENDING ────► Manual Review     │   │
│  │  PEP/Sanctions Hit     ────► SUSPENDED ──► DB Only ❌        │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```


# IV. Other API
### UPDATE KYC (While PENDING) & Create Block After Success Verified

Set Request:

| Setting | Value |
|---|---|
| `Method` | PUT |
| `URL` | http://localhost:8080/api/v1/kyc |

Set Header

| Key | Value |
|---|---|
| `Authorization` | Bearer {{access_token}} |

Set Request Body (JSON)
```json
{
    "customer_id": "CUSa1b2c3d4e5f6",
    "first_name": "Test",
    "last_name": "Test Update",
    "phone": "+85599999999",
    "description": "Updated phone number"
}
```