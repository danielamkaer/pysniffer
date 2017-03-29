import logging
logger = logging.getLogger(__name__)

class EventHandler:
    def __init__(self, handler, filt=None):
        self.handler = handler
        self.filt = filt

    async def __call__(self, *args, **kwargs):
        if callable(self.filt):
            match = False
            try:
                match = self.filt(*args, **kwargs)
            except AttributeError:
                pass
            except Exception:
                logger.error("event filter caused an exception", exc_info=1)
            if match:
                await self.handler(*args, **kwargs)
        else:
            await self.handler(*args, **kwargs)

class Event:
    def __init__(self):
        self.handlers = set()

    def handle(self, handler):
        if type(handler) == tuple:
            h = EventHandler(handler[0], handler[1])
        else:
            h = EventHandler(handler)
        self.handlers.add(h)
        return self

    def unhandle(self, handler):
        for h in self.handlers:
            if h.handler == handler:
                handler = h
                break
        try:
            self.handlers.remove(handler)
        except:
            raise ValueError("Handler is not handling this event, so cannot unhandle it.")
        return self

    async def fire(self, *args, **kargs):
        for handler in self.handlers.copy():
            await handler(*args, **kargs)

    def getHandlerCount(self):
        return len(self.handlers)

    def __repr__(self):
        return "Event(%s)" % set.__repr__(self.handlers)

    __iadd__ = handle
    __isub__ = unhandle
    __call__ = fire
    __len__  = getHandlerCount