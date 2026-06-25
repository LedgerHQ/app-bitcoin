from ragger.navigator import NavInsID

MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER = 16
# On Nano X we have reduced the max. number of handled outputs
# to reduce the stack consumption limited to 8k
MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER_NANOX = 8

def get_max_ext_output_simplified_number(model):
    """Returns the device-specific MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER.
    Nano X has a lower limit (MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER_NANOX)
    due to memory constraints."""
    if hasattr(model, 'name') and model.name == "nanox":
        return MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER_NANOX
    return MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER

class Instructions:
    def __init__(self, model):
        self.data = {
            'text': [],
            'instruction_until_text': [],
            'instruction_on_text': [],
            'save_screenshot': []
        }

        if not model:
            raise Exception("Model must be specified")

        self.model = model

    def __str__(self):
        return "Data: {0}\n\t".format(self.data)

    def same_request(self, text, instruction_until_text=NavInsID.RIGHT_CLICK,
                     instruction_on_text=NavInsID.BOTH_CLICK, save_screenshot=True):

        self.data['text'][-1].append(text)
        self.data['instruction_until_text'][-1].append(instruction_until_text)
        self.data['instruction_on_text'][-1].append(instruction_on_text)
        self.data['save_screenshot'][-1].append(save_screenshot)

    def new_request(self, text, instruction_until_text=NavInsID.RIGHT_CLICK,
                    instruction_on_text=NavInsID.BOTH_CLICK, save_screenshot=True):

        self.data['text'].append([text])
        self.data['instruction_until_text'].append([instruction_until_text])
        self.data['instruction_on_text'].append([instruction_on_text])
        self.data['save_screenshot'].append([save_screenshot])

    def nano_skip_screen(self, text, save_screenshot=True):
        self.new_request(text, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK,
                         save_screenshot=save_screenshot)

    def review_start(self, output_count: int = 1, save_screenshot=True, has_warning=False):
        self.new_request("Review", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                        save_screenshot=save_screenshot)

        if has_warning:
            self.same_request("Security risk detected", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                            save_screenshot=save_screenshot)

        for output_index in range(0, output_count):
            # the initial N_CACHED_EXTERNAL_OUTPUTS outputs are cached, so it is the same request
            if output_index < get_max_ext_output_simplified_number(self.model):
                self.same_request("Amount", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                            save_screenshot=save_screenshot)
            else:
                self.new_request("Amount", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                            save_screenshot=save_screenshot)
    def review_fees(self, fees_on_same_request: bool = True, save_screenshot=True):
        if fees_on_same_request:
            self.same_request("Fees", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                         save_screenshot=save_screenshot)
        else:
            self.new_request("Fees", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                         save_screenshot=save_screenshot)

    def confirm_transaction(self, save_screenshot=True):
        self.same_request("Sign transaction", NavInsID.USE_CASE_REVIEW_TAP,
                          NavInsID.USE_CASE_REVIEW_CONFIRM, save_screenshot=save_screenshot)
        self.new_request("Transaction", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_STATUS_DISMISS,
                         save_screenshot=save_screenshot)

    def review_message(self, save_screenshot=True):
        self.new_request("Review", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_REVIEW_TAP, save_screenshot=save_screenshot)
        self.same_request("Message", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_REVIEW_TAP, save_screenshot=save_screenshot)

    def confirm_message(self, save_screenshot=True):
        self.same_request("Sign", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_REVIEW_CONFIRM, save_screenshot=save_screenshot)
        self.new_request("Message", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_STATUS_DISMISS,  save_screenshot=save_screenshot)

    def confirm_wallet(self, save_screenshot=True):
        self.new_request("Approve", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_CONFIRM,
                         save_screenshot=save_screenshot)
        self.same_request("Wallet", NavInsID.USE_CASE_REVIEW_TAP,
                          NavInsID.USE_CASE_STATUS_DISMISS, save_screenshot=save_screenshot)

    def reject_message(self, save_screenshot=True):
        self.new_request("Review", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_REVIEW_TAP, save_screenshot=save_screenshot)
        self.same_request("Message", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_REJECT,
                         save_screenshot=save_screenshot)
        self.same_request("Reject", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_CONFIRM,
                          save_screenshot=save_screenshot)
        self.new_request("Message", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_STATUS_DISMISS,
                         save_screenshot=save_screenshot)

    def address_confirm(self, save_screenshot=True):
        self.new_request("Confirm", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
                         save_screenshot=save_screenshot)
        self.same_request("Address verified", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.CANCEL_FOOTER_TAP,
                save_screenshot=save_screenshot)

    def choice_confirm(self, confirm_text = "Approve", save_screenshot=True):
        self.new_request(confirm_text, NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_CONFIRM,
                         save_screenshot=save_screenshot)

    def choice_reject(self, reject_text = "Approve", save_screenshot=True):
        self.new_request(reject_text, NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_REJECT,
                         save_screenshot=save_screenshot)

    def status_dismiss(self, text, status_on_same_request=True, save_screenshot=True):
        if status_on_same_request:
            self.same_request(text, NavInsID.USE_CASE_REVIEW_TAP, NavInsID.CANCEL_FOOTER_TAP,
                         save_screenshot=save_screenshot)
        else:
            self.new_request(text, NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_STATUS_DISMISS,
                         save_screenshot=save_screenshot)
