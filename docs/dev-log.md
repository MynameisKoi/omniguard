# Dev Log

My notes while building the OmniGuard dashboard + backend + frontend + MongoDB. Newest on top.

---

## Fri, Sept 18 2026
Worked on a lot of things

Mongo
- set up local mongodb 
- connected that with python drivers
- made alerts persist on mongodb collection


Integration of Khoi's engine with API 
- Ran Spectra2 and checked the API - worked the first try 
- Beacon -> his detector -> POST -> MONGO -> Dashboard
- Added dst_ip and confidence in the alert 


Integration of Rahim's verifeye 
- Ran the code and works for github login page

Neo4j
- Installed, and ran some tests locally 
- Siddik is working on it for now 



## Fri, Sep 11 2026

Goal for today: get one alert to go from the backend to the frontend and show up on screen. Basic frontend, basic backend, that's it. No Neo4j or Kafka yet, saving that for later.

Using FastAPI for the backend and React for the frontend.

Why FastAPI — it validates the data for me and gives me an auto docs page where I can test my endpoints without writing a frontend first. 

### Setting up the env

Made the virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install "fastapi[standard]" uvicorn
pip freeze > requirements.txt

Looks good