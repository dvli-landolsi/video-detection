from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from ..models.user import User
from ..models.response import VideoResponse
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader
import uuid
from ..models.api_key import ApiKey

router = APIRouter()


api_key_header = APIKeyHeader(name="X-API-Key")



async def get_api_key(api_key_header: str = Security(api_key_header)) -> str:
    key = await ApiKey.find_one(ApiKey.value == api_key_header)
    if key:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )



@router.get("/all-users")
async def get_all_users(api_key: str = Security(get_api_key)):
    try:
        users = await User.find().to_list()
        return {"users":users}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/all-responses")
async def get_all_responses(api_key: str = Security(get_api_key)):
    try:
        responses = await VideoResponse.find().to_list()
        print("responses",responses)
        return {"responses":responses}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
    


@router.get("/generate-api-key")
async def generate_api_key():
    try:
        api_key = str(uuid.uuid4())
        api_key_obj = ApiKey(value=api_key)
        await ApiKey.insert_one(api_key_obj)
        return {"api_key":api_key, "status":"success"}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
    



@router.get("/get-response-by-api-key")
async def get_response_by_api_key(api_key: str = Security(get_api_key)):
    try:
        # Fetch the data from the database
        response = await VideoResponse.find(VideoResponse.api_key == api_key).to_list()

        # Convert the database objects to the Pydantic model
        # response_data = [VideoResponse.from_orm(res) for res in response]

        return response
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))