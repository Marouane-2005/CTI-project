from fastapi import FastAPI

app = FastAPI(title="CTI Application", version="1.0.0")

@app.get("/")
def read_root():
    return {"message": "CTI Application is running"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}