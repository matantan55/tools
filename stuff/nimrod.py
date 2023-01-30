from pynput.keyboard import Events
import sys
from io import StringIO


class OutputManager:
    def __init__(self) -> None:
        """
        class constructor
        """
        self.output_flow: bool = True
        self.old = sys.stdout
        self.tmp = StringIO

    def flow_flip(self) -> None:
        """
        this function stops and restarts the flow of the output in the program.
        :return: None
        """
        if not self.output_flow:
            self.old = sys.stdout
            sys.stdout = self.tmp = StringIO()
        else:
            sys.stdout = self.old
            print(self.tmp.getvalue())


def main() -> None:
    """
    Main
    :return: None
    """
    im = OutputManager()
    with Events() as events:
        for e in events:
            if str(type(e)) == "<class 'pynput.keyboard.Events.Press'>":
                if "." in str(e):
                    tmp = str(e).split(".")[-1][:-1]
                    if tmp == "esc":
                        im.output_flow = not im.output_flow
                        im.flow_flip()
                    print(tmp)
                else:
                    print(e.key)


if __name__ == "__main__":
    main()
