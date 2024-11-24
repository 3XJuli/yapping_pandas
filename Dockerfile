FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG C.UTF-8 

RUN apt-get update && apt-get install build-essential curl openssh-client git software-properties-common -y

RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get install python3.11 python3-pip libpython3.11-dev python3.11-distutils -y
RUN python3 -m pip install --upgrade setuptools

RUN curl -sSL https://install.python-poetry.org | python3.11 -
ENV PATH="/root/.local/bin:$PATH"

RUN mkdir -p $HOME/.cache/pypoetry/virtualenvs/

RUN mkdir /src

COPY ./poetry.lock /src/
COPY ./pyproject.toml /src/
COPY ./src /src/src

WORKDIR /src

RUN poetry env use python3.11

RUN poetry install --no-root --without dev

EXPOSE 80

CMD ["poetry", "run", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]