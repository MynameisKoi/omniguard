# Dev Log

My notes while building the OmniGuard dashboard + backend. Newest on top.

---

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