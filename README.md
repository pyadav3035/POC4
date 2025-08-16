# Project Documentation

## Setup and Deployment

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-folder>
    ```

2.  **Configure environment variables:**
    - Copy `.env.example` to `.env` in each service directory and update the values as needed.

3.  **Build and run the application:**
    ```bash
    docker-compose up --build
    ```

4.  **Access the application:**
    - Frontend: `http://localhost`
    - Auth Service API: `http://localhost/api/auth/`
    - SFD Service API: `http://localhost/api/sfd/`
