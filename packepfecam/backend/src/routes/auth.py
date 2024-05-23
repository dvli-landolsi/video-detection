from datetime import datetime, timedelta
from bson.objectid import ObjectId
from fastapi import APIRouter, Response, status, Depends, HTTPException, Path
from ..models.user import User, Login, Register, UserResponse
from .. import utils
from .. import oauth2
from fastapi_jwt_auth import AuthJWT
from ..config.settings import settings

router = APIRouter()
ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN


# Register new User - to be removed if webapp is private
@router.post(
    "/register", status_code=status.HTTP_201_CREATED, response_model=UserResponse
)
async def create_user(credentials: Register):
    if not utils.is_valid_email(credentials.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email"
        )
    if not utils.is_valid_phone_number(credentials.phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid phone number"
        )

    user_exists = await User.find_one(User.username == credentials.username)
    email_exists = await User.find_one(User.email == credentials.email)
    phone_number_exists = await User.find_one(
        User.phone_number == credentials.phone_number
    )
    if user_exists or email_exists or phone_number_exists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Account already exists"
        )

    new_user = User(
        username=credentials.username,
        email=credentials.email.lower(),
        phone_number=credentials.phone_number,
        password=utils.hash_password(credentials.password),
        created_at=datetime.utcnow(),
        department=credentials.department,
        role=credentials.role,
    )

    #     await new_user.create()

    # Generate a verification code and send it to the user's email
    verification_code = utils.generate_verification_code()
    await utils.send_verification_email(new_user.email, verification_code)
    new_user.verification_code = verification_code
    await new_user.save()

    r_user = UserResponse(
        username=new_user.username,
        email=new_user.email,
        phone_number=new_user.phone_number,
        department=new_user.department,
        role=new_user.role,
        message="User registered. Check your email for verification.",
    )

    return r_user


async def send_verification_email(to_email: str, verification_code: str):
    await utils.send_verification_email(to_email, verification_code)


@router.post("/verify-email")
async def verify_email(email: str, verification_code: str):
    user = await User.find_one({"email": email, "verification_code": verification_code})

    if not user:
        raise HTTPException(status_code=404, detail="User not found or invalid code")

    # Mark the user as verified in the database
    user.is_verified = True
    await user.save()

    return {"message": "Email verified successfully"}


# Sign In user
@router.post("/login")
async def login(credentials: Login, response: Response, Authorize: AuthJWT = Depends()):
    user = await User.find_one(
        User.username == credentials.username,
        User.email == credentials.email,
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found, Please check your username or email",
        )

    # email verified or not
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    if not utils.verify_password(credentials.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password",
        )

    #     # Create access token

    access_token = Authorize.create_access_token(
        subject=str(user.id), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN)
    )

    refresh_token = Authorize.create_refresh_token(
        subject=str(user.id), expires_time=timedelta(minutes=REFRESH_TOKEN_EXPIRES_IN)
    )

    # Store refresh and access tokens in cookie
    response.set_cookie(
        "access_token",
        access_token,
        ACCESS_TOKEN_EXPIRES_IN * 60,
        ACCESS_TOKEN_EXPIRES_IN * 60,
        "/",
        None,
        False,
        True,
        "lax",
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        REFRESH_TOKEN_EXPIRES_IN * 60,
        REFRESH_TOKEN_EXPIRES_IN * 60,
        "/",
        None,
        False,
        True,
        "lax",
    )
    response.set_cookie(
        "logged_in",
        "True",
        ACCESS_TOKEN_EXPIRES_IN * 60,
        ACCESS_TOKEN_EXPIRES_IN * 60,
        "/",
        None,
        False,
        False,
        "lax",
    )

    # Send both access
    return {"status": "success", "access_token": access_token}


# Refresh Acess Token
@router.get("/refresh")
async def refresh_token(response: Response, Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_refresh_token_required()

        user_id = Authorize.get_jwt_subject()

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not refresh access token",
            )

        user = await User.get(user_id)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="The user belonging to this token no logger exist",
            )
        access_token = Authorize.create_access_token(
            subject=str(user.id),
            expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN),
        )
    except Exception as e:
        error = e.__class__.__name__
        if error == "MissingTokenError":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Please provide refresh token",
            )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)

    response.set_cookie(
        "access_token",
        access_token,
        ACCESS_TOKEN_EXPIRES_IN * 60,
        ACCESS_TOKEN_EXPIRES_IN * 60,
        "/",
        None,
        False,
        True,
        "lax",
    )
    response.set_cookie(
        "logged_in",
        "True",
        ACCESS_TOKEN_EXPIRES_IN * 60,
        ACCESS_TOKEN_EXPIRES_IN * 60,
        "/",
        None,
        False,
        False,
        "lax",
    )

    return {"access_token": access_token}


# Logout user
@router.get("/logout", status_code=status.HTTP_200_OK)
def logout(
    response: Response,
    Authorize: AuthJWT = Depends(),
    user_id: str = Depends(oauth2.require_user),
):
    Authorize.unset_jwt_cookies()
    response.set_cookie("logged_in", "", -1)

    return {"status": "success"}
