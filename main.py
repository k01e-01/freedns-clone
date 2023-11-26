from typing import Annotated
import os
import dotenv

import yaml
import bcrypt
import requests
import base64

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from starlette.status import ( 
    HTTP_403_FORBIDDEN, 
    HTTP_200_OK,
)
from pydantic import BaseModel

# run code with 'uvicorn main:app' to run the actual app
# run code with 'python main.py' to add new token



def append_token():
    subname = input("new subname > ")
    token = base64.b64encode(os.urandom(32))

    print(f"token: {token.decode('ascii')}")

    hashed_token = bcrypt.hashpw(token, bcrypt.gensalt())

    with open("auth.yaml", 'r') as authfile:
        auth = yaml.safe_load(authfile)

    auth[subname] = hashed_token.decode("utf-8")

    with open("auth.yaml", 'w') as authfile:
        yaml.safe_dump(auth, authfile)

if __name__ == "__main__":
    append_token()
    exit()



DOMAIN = "isso.moe"
DESEC_URL = "https://desec.io/api/v1"

dotenv.load_dotenv()
desec_token: str | None = os.getenv("DESEC_TOKEN")
if desec_token is None:
    raise OSError("DESEC_TOKEN enviroment variable not set or not in .env")

app = FastAPI()


# parsing json in fastapi requires this for some reason
class NameSetModel(BaseModel):
    ttl: int
    records: list[str]


# check authentication, if good, return None
def auth_check(subname: str, token: str | None) -> JSONResponse | None:
    if token is None:
        return JSONResponse(
            "Must have token provided in Token header!", 
            status_code=HTTP_403_FORBIDDEN,
        )

    # hashed_token is from the yaml
    try:
        with open("auth.yaml", 'r') as auth:
            hashed_token: str = yaml.safe_load(auth)[subname]
    except KeyError:
        hashed_token: str = ""

    if not bcrypt.checkpw(
        token.encode("utf-8"), 
        hashed_token.encode("utf-8"),
    ):
        return JSONResponse(
            "Subname and token do not match.",
            status_code=HTTP_403_FORBIDDEN,
        )

    return None


@app.get("/subname/{subname}", status_code=HTTP_200_OK)
def nameread(
    subname: str, 
    Token: Annotated[str | None, Header()] = None,
):
    ret = auth_check(subname, Token)
    if ret is not None:
        return ret

    return JSONResponse(requests.get(
        url = DESEC_URL + f"/domains/{DOMAIN}/rrsets/{subname}/A/",
        headers = {
            "Authorization": f"Token {desec_token}",
            "Content-Type": "application/json",
        }
    ).json())


@app.put("/subname/{subname}", status_code=HTTP_200_OK)
def nameset(
    subname: str,
    body: NameSetModel,
    Token: Annotated[str | None, Header()] = None,
):
    ret = auth_check(subname, Token)
    if ret is not None:
        return ret

    return JSONResponse(requests.patch(
        url = DESEC_URL + f"/domains/{DOMAIN}/rrsets/{subname}/A/",
        headers = {
            "Authorization": f"Token {desec_token}",
            "Content-Type": "application/json",
        }, 
        json = {
            "ttl": body.ttl,
            "records": body.records,
        }
    ).json())
