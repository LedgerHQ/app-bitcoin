from ragger.navigator import NavInsID


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

    def navigate_end_of_flow(self, save_screenshot=True):
        self.new_request("Processing", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                         save_screenshot=save_screenshot)

    def confirm_transaction(self, save_screenshot=True):
        self.new_request("Sign", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_CONFIRM,
                         save_screenshot=save_screenshot)
        self.new_request("TRANSACTION", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_STATUS_DISMISS,
                         save_screenshot=save_screenshot)

    def same_request_confirm_transaction(self, save_screenshot=True):
        self.same_request("Sign", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_CONFIRM,
                          save_screenshot=save_screenshot)
        self.new_request("TRANSACTION", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_STATUS_DISMISS,
                         save_screenshot=save_screenshot)

    def confirm_message(self, save_screenshot=True):
        self.new_request("Sign", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_REVIEW_CONFIRM, save_screenshot=save_screenshot)
        self.new_request("MESSAGE", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_STATUS_DISMISS,  save_screenshot=save_screenshot)

    def confirm_wallet(self, save_screenshot=True):
        self.new_request("Approve", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_CONFIRM,
                         save_screenshot=save_screenshot)
        self.same_request("WALLET", NavInsID.USE_CASE_REVIEW_TAP,
                          NavInsID.USE_CASE_STATUS_DISMISS, save_screenshot=save_screenshot)

    def reject_message(self, save_screenshot=True):
        self.new_request("Sign", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_REJECT,
                         save_screenshot=save_screenshot)
        self.same_request("Reject", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_CONFIRM,
                          save_screenshot=save_screenshot)
        self.new_request("MESSAGE", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_STATUS_DISMISS,
                         save_screenshot=save_screenshot)

    def warning_accept(self, save_screenshot=True):
        self.new_request("Warning", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_CONFIRM,
                         save_screenshot=save_screenshot)

    def address_confirm(self, save_screenshot=True):
        self.new_request("Confirm", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
                         save_screenshot=save_screenshot)

    def choice_confirm(self, save_screenshot=True):
        self.new_request("Approve", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_CONFIRM,
                         save_screenshot=save_screenshot)

    def choice_reject(self, save_screenshot=True):
        self.new_request("Approve", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_REJECT,
                         save_screenshot=save_screenshot)

    def footer_cancel(self, save_screenshot=True):
        self.new_request("Approve", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.CANCEL_FOOTER_TAP,
                         save_screenshot=save_screenshot)
