class ErrorHandler:
    @staticmethod
    def extrinsic_failed(extrinsic_result):
        """
        Checks if there is `SystemEvent.ExtrinsicFailed` in the list of
        transaction events within the given `extrinsic_result`.

        :param extrinsic_result: The result of a submission.
        :returns: Whether the extrinsic submission failed.
        """
        for event in extrinsic_result['events']:
            if event['event']['section'] == 'system' and event['event']['method'] == 'ExtrinsicFailed':
                return True
        return False

    @staticmethod
    def extrinsic_successful(extrinsic_result):
        """
        Checks if there is `SystemEvent.ExtrinsicSuccess` in the list of
        transaction events within the given `extrinsic_result`.

        :param extrinsic_result: The result of a submission.
        :returns: Whether the extrinsic submission succeeded.
        """
        for event in extrinsic_result['events']:
            if event['event']['section'] == 'system' and event['event']['method'] == 'ExtrinsicSuccess':
                return True
        return False

    @staticmethod
    def get_extrinsic_error(extrinsic_result):
        """
        Get the extrinsic error from the transaction result.

        :param extrinsic_result: The transaction result.
        :returns: The extrinsic error.
        """
        error_event = extrinsic_result.get('dispatchError', None)
        
        if error_event and error_event['isModule']:
            module_error = error_event['asModule']
            try:
                return module_error['registry'].find_meta_error(module_error)
            except:
                # If finding meta error fails, return the error_event itself
                return error_event
        return error_event or None
