
import smhasher
import timeit

print('smhasher version: %s\n\n' % smhasher.__version__)

def demo(name, seed=None):
    text = 'samplebias' * 10
    func = getattr(smhasher, name)
    msg = name
    if seed:
        msg += ' seed: %d' % seed
        res = func(text, seed)
    else:
        res = func(text)
    print('%s\n  %d\n  %s\n' % (msg, res, hex(res)))

def demoprogressive(name, seed=0):
    text = 'samplebias' * 10
    process = getattr(smhasher, name + '_process')
    result = getattr(smhasher, name + '_result')
    msg = name
    if seed:
        msg += ' seed: %d' % seed
    carry = 0
    for c in text:
        seed, carry = process(seed, carry, c)
    res = result(seed, carry, len(text))
    print('%s\n  %d\n  %s\n' % (msg, res, hex(res)))

demo('murmur3_x86_64')
demo('murmur3_x86_64', 123)

demo('murmur3_x86_128')
demo('murmur3_x64_128')
demo('murmur3_x86_128', 123456789)

demoprogressive('pmurhash32')
demoprogressive('pmurhash32', 42)
demoprogressive('pmurhash128')
demoprogressive('pmurhash128', 0x4242424242)

# timing comparison with str __hash__
t = timeit.Timer("smhasher.murmur3_x86_64('hello')", "import smhasher")
print('smhasher.murmur3:', t.timeit())

t = timeit.Timer("str.__hash__('hello')")
print('    str.__hash__:', t.timeit())


