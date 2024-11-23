from fastapi import HTTPException, status


class ObjectNotFound(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Failed to retrieve object. Object not found",
        )


class ForeignObjectNotFound(HTTPException):
    def __init__(self, name, id):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Failed to retrieve associated {name} object. Id {id} not found",
        )


class ObjectAlreadyExists(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to insert object. Object already exists",
        )


class FailedToRetrieveObject(HTTPException):
    """
    Raised when an object cannot be retrieved from the database
    => differs from ObjectNotFound: In this case we know the object exists but fail to retrieve it unexpectedly
    """

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve object from database",
        )


class IdGeneratedAlways(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Id is generated always. Cannot be set manually.",
        )
