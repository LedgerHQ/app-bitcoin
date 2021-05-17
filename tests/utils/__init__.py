
def automation(filename):
    """Decorator that adds the automation_file attribute to a test function.

    When present, this filename will be used as the --automation file when creating the speculos fixture.
    """
    def decorator(func):
        func.automation_file = filename
        return func
    return decorator