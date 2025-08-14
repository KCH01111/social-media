from tornado.ioloop import IOLoop

async def es_io(fn, *a, **kw):
    return await IOLoop.current().run_in_executor(None, lambda: fn(*a, **kw))

async def cpu_io(fn, *a, **kw):
    return await IOLoop.current().run_in_executor(None, lambda: fn(*a, **kw))
