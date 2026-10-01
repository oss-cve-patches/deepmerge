var merge = require('../')
var test = require('tape')
var isMergeableObject = require('is-mergeable-object')

test('merging objects with own __proto__', function(t) {
	var user = {}
	var malicious = JSON.parse('{ "__proto__": { "admin": true } }')
	var mergedObject = merge(user, malicious)
	t.notOk(mergedObject.__proto__.admin, 'non-plain properties should not be merged')
	t.notOk(mergedObject.admin, 'the destination should have an unmodified prototype')
	t.end()
})

test('merging objects with plain and non-plain properties', function(t) {
	var plainSymbolKey = Symbol('plainSymbolKey')
	var parent = {
		parentKey: 'should be undefined'
	}
	
	var target = Object.create(parent)	
	target.plainKey = 'should be replaced'
	target[plainSymbolKey] = 'should also be replaced'
	
	var source = {
		parentKey: 'foo',
		plainKey: 'bar',
		newKey: 'baz',
		[plainSymbolKey]: 'qux'
	}
	
	var mergedObject = merge(target, source)
	t.equal(undefined, mergedObject.parentKey, 'inherited properties of target should be removed, not merged or ignored')
	t.equal('bar', mergedObject.plainKey, 'enumerable own properties of target should be merged')
	t.equal('baz', mergedObject.newKey, 'properties not yet on target should be merged')
	t.equal('qux', mergedObject[plainSymbolKey], 'enumerable own symbol properties of target should be merged')
	t.end()
})

// the following cases come from the thread here: https://github.com/TehShrike/deepmerge/pull/164
test('merging strings works with a custom string merge', function(t) {
	var target = { name: "Alexander" }
	var source = { name: "Hamilton" }
	function customMerge(key, options) {
		if (key === 'name') {
			return function(target, source, options) {
				return target[0] + '. ' + source.substring(0, 3)
			}
		} else {
			return merge
		}
	}

	function mergeable(target) {
		return isMergeableObject(target) || (typeof target === 'string' && target.length > 1)
	}

	t.equal('A. Ham', merge(target, source, { customMerge: customMerge, isMergeableObject: mergeable }).name)
	t.end()
})

test('merging objects with null prototype', function(t) {
	var target = Object.create(null)
	var source = Object.create(null)
	target.wheels = 4
	target.trunk = { toolbox: ['hammer'] }
	source.trunk = { toolbox: ['wrench'] }
	source.engine = 'v8'
	var expected = {
		wheels: 4,
		engine: 'v8',
		trunk: {
			toolbox: ['hammer', 'wrench' ]
		}
	}

	t.deepEqual(expected, merge(target, source))
	t.end()
})

// CVE-2026-93753: __proto__ keys must be dropped regardless of what the target looks like
function assertNotPoisoned(t, result, expectedPrototype) {
	t.equal(Object.getPrototypeOf(result), expectedPrototype, 'the result should have an unmodified prototype')
	t.notOk(result.isAdmin, 'the result should not inherit attacker-controlled properties')
	t.notOk(({}).isAdmin, 'Object.prototype should not be polluted')
}

test('merging __proto__ into a null-prototype target', function(t) {
	var malicious = JSON.parse('{ "__proto__": { "isAdmin": true } }')
	var mergedObject = merge(Object.create(null), malicious)
	assertNotPoisoned(t, mergedObject, Object.prototype)
	t.notOk(Object.prototype.hasOwnProperty.call(mergedObject, '__proto__'), 'the __proto__ key should be dropped')
	t.end()
})

test('merging __proto__ over a null placeholder in the target', function(t) {
	var malicious = JSON.parse('{ "a": { "__proto__": { "isAdmin": true } } }')
	var mergedObject = merge({ a: null }, malicious)
	assertNotPoisoned(t, mergedObject.a, Object.prototype)
	t.end()
})

test('merging __proto__ over a primitive placeholder in the target', function(t) {
	var malicious = JSON.parse('{ "a": { "__proto__": { "isAdmin": true } } }')
	var mergedObject = merge({ a: 1 }, malicious)
	assertNotPoisoned(t, mergedObject.a, Object.prototype)
	t.end()
})

test('merging a target that has its own __proto__ key', function(t) {
	var target = JSON.parse('{ "__proto__": { "isAdmin": true }, "name": "defaults" }')
	var mergedObject = merge(target, { other: 'value' })
	assertNotPoisoned(t, mergedObject, Object.prototype)
	t.equal(mergedObject.name, 'defaults', 'other target keys should still be merged')
	t.equal(mergedObject.other, 'value', 'source keys should still be merged')
	t.end()
})

test('merging arrays whose elements contain __proto__', function(t) {
	var poisoned = JSON.parse('{ "__proto__": { "isAdmin": true } }')
	Object.setPrototypeOf(poisoned, null)
	var merged = merge([], [ poisoned ])
	assertNotPoisoned(t, merged[0], Object.prototype)
	t.end()
})

test('merge.all with __proto__ in a null-prototype object', function(t) {
	var malicious = JSON.parse('{ "a": { "__proto__": { "isAdmin": true } } }')
	var mergedObject = merge.all([ { a: null }, malicious ])
	assertNotPoisoned(t, mergedObject.a, Object.prototype)
	t.end()
})

test('merging __proto__ with clone: false', function(t) {
	var malicious = JSON.parse('{ "__proto__": { "isAdmin": true } }')
	var mergedObject = merge(Object.create(null), malicious, { clone: false })
	assertNotPoisoned(t, mergedObject, Object.prototype)
	t.end()
})

test('keys named constructor and prototype are still merged as data', function(t) {
	var target = Object.create(null)
	target.constructor = { a: 1 }
	var source = Object.create(null)
	source.constructor = { b: 2 }
	source.prototype = 'value'
	var mergedObject = merge(target, source)
	t.deepEqual(mergedObject.constructor, { a: 1, b: 2 }, 'constructor key should be deep merged')
	t.equal(mergedObject.prototype, 'value', 'prototype key should be merged')
	t.notOk(({}).b, 'Object.prototype should not be polluted')
	t.end()
})
