import logging


def at1(text: str) -> str:
    yield "hello"
    yield "world"
    yield text


for i in at1("!"):
    print(i)
logging.basicConfig(level=logging.INFO)
logging.info("hello")

print([1,2] + [3, 4])