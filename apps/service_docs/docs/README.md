# INDX documentation generation

Generate docuementation by interpreting JavaScript and structured comments
within the source code. Comment style inspired by JavaDoc.



## Config files

* `basePath` - Where to look for files to document
* `files` - List of files to parse. Order matters - if you have a class in
   file A that extends a class in file B, B should be before A. Globs may be
   used (e.g. js/*.js)
* `require` - Same as files, except this files with not be shown in the
   documentation (i.e, they will be used for inheritance only). Useful if you
   extend other files.
* `project` - Attributes about the project put at the top of the
   documentation: `title`, `version`, `description` (in markdown).

## Comment Style

docsgen will attempt to automatically extract classes and methods from your
sourcecode. For each of these, the preceding comment is parsed. Comment lines
must begin with 3 slashes (`///`) to be used for documentation.

A docsgen comment begins with a description and is followed by tags (if any). A tag is of the form @tag [parameters]. Descriptions should be in [Markdown](http://en.wikipedia.org/wiki/Markdown). The description may come after the tags if preferred.

For example, both of the following are valid ways of describing a class:

	/// This awesome class does
	/// some awesome things!
	///
	/// @title My awesome class

and

	/// @title My awesome class
	///
	/// This awesome class does
	/// some awesome things!


## Files

**Placement**

Docsgen comment should be at top of file. Other comments and blank lines may
precede it, but all code must be after the Docsgen comment.

**Tags**

| Tag / parameters	| Description 									| Repeatable | Default  |
|-------------------|-----------------------------------------------|------------|----------|
| `@title title` 	| Title of file.								| No | Filename |
| `@version` 		| Version of file. Not yet implemented			| No | -        |
| `@author name <email@address.com>` | Author name and optionally email address. Not yet implemented	| Yes, for each author | - |
| `@since date` 	| Describes when the functionality first existed. Not yet implemented | No | - |
| `@see url` 		| Url to additional documentation. Not yet implemented | Yes, for each relevant source | - |

**Example**

	/// This library does awesome magical things. Also, I can
	/// have some *markdown* in here - isn't that **awesome**?
	///
	/// @title Some Awesome Library



## Classes

**Placement**

Comment should precede the class.

**Auto detection**

A class must have a name beginning with a capital letter and may be defined in
any of the following forms:

```javascript
Animal = function () {
Animal: function () {
world.Animal = function () {
function Animal () {

// The backbone extend form is also allowed:
something.awesome.Animal = SomeSuperClass.extend({
```


**Tags**

| Tag / parameters	| Description 									| Repeatable | Default 	|
|-------------------|-----------------------------------------------|------------|----------|
| `@class`          | Force the docsgen comment to be describing a class | No | Only if class is detected |
| `@ignore` 		| Ignore this class (do not document it).		| No         | Only if class name begins with `_` in source		|
| `@extend Some.SuperClass url` | Indicate that this class extends another. If a url to documentation is not provided, docsgen will try to find the class within the sourcecode. Also `@extends` and `@augments`. | Yes, for multiple inheritence | Superclass if .extend is used within source code |
| `@name ClassName` | Name of class. | No | Name within source code |
| `@fullName theFull.ClassName` | Full name of class (including object in which it resides). By default, this will be the value of @name. | No | Full name within source code |
| `@instanceName className` | An example instance name. E.g., instanceName of Cow might be "cow" or "daisy". | No | Classname with first letter lowercase |
| `@order n` 		| Force a particular order for the class within the documentation. | No | Order in source code |
| `@since date` 	| Describes when the functionality first existed. Not yet implemented | No | - |
| `@see url` 		| Url to additional documentation. Not yet implemented | Yes, for each relevant source | - |
| `@deprecated description` | Describes outdated functionality. Not yet implemented | No | - |
| `@alias name` | This class is available under a different name. Not yet implemented. | Yes | - |

**Example**

	/// @name Cow
	/// @fullName farm.Cow
	/// @instanceName daisy
	/// @extend Animal
	///
	/// This is my cow class. I use *daisy* as an example cow.


## Attributes

**Placement**

Comment should precede the attribute.

**Auto detection**

An attribute may be of the following form:

```javascript
something.something = blah
something: blah
```

Attributes beginning with `_` will be considered private and will not be shown
in the generated docs.

**Tags**

| Tag / parameters	| Description 									| Repeatable | Default 	|
|-------------------|-----------------------------------------------|------------|----------|
| `@attribute`          | Force the docsgen comment to be describing an attribute | No | Only if class is detected |
| `@name attrName` | Name of the attribute. Not yet implemented | No | Detected within code |
| `@optional` | If specified, indicates that the attribute is optional | No | - |
| `@types {types}` | Types that the attribute may be | No | - |
| `@ignore` | Ignore this method (do not document it) (auto-detected if name begins with _). Not yet implemented | No | Only if method name begins with `_` in source		 |
| `@order n` | Force a particular order for the method (auto-detected by order within code). | No | Order in source code |
| `@since date` | Describes when the functionality first existed. Not yet implemented | No | - |
| `@see url` | Url to additional documentation. Not yet implemented | Yes, for each relevant source | - |
| `@deprecated description` | Describes outdated functionality. Not yet implemented | No | - |
| `@alias name` | This attribute is available under a different name. Not yet implemented. | Yes | - |
| `@default value` | The default value for the attribute. Not yet implemented. | No | - |

## Methods

**Placement**

Comment should precede the method.

**Auto detection**

A method may be of the following form:

```javascript
something.something = function () {
something: function () {
```

Methods beginning with `_` will be considered private and will not be shown in
the generated docs.

**Tags**

| Tag / parameters	| Description 									| Repeatable | Default 	|
|-------------------|-----------------------------------------------|------------|----------|
| `@method`          | Force the docsgen comment to be describing a method | No | Only if class is detected |
| `@arg {types} name - comment` | Describe an argument. Use @opt if optional. | Yes, for multiple arguments | Arguments in function definition within source code |
| `@return {types} - comment` | Synchronous return | Yes, for multiple return conditions | - |
| `@then {types} name, ... - comment` or `@fail {types} name, ... - comment` | Asynchronous return | Yes, for multiple result conditions | - |
| `@chain` | Chaining return (i.e., returns `this`) | No | - |
| `@name methodName` | Name of the method. Not yet implemented | No | Detected within code |
| `@ignore` | Ignore this method (do not document it) (auto-detected if name begins with _). Not yet implemented | No | Only if method name begins with `_` in source		 |
| `@order n` | Force a particular order for the method (auto-detected by order within code). | No | Order in source code |
| `@throws {types} - comment` | Describe when an exception is thrown (may also use `@exception`). Not yet implemented | Yes, for each exception | - |
| `@since date` | Describes when the functionality first existed. Not yet implemented | No | - |
| `@see url` | Url to additional documentation. Not yet implemented | Yes, for each relevant source | - |
| `@deprecated description` | Describes outdated functionality. Not yet implemented | No | - |
| `@private` or `@protected` or `@public` | Also `@access public` etc. Not yet implemented | No | - |
| `@alias name` | This method is available under a different name. Not yet implemented. | Yes | - |

**Example** (asynchronous method)

	/// @arg {string|number} boxid - the id for the box
	///
	/// @then ({Box} the box)
	/// @fail ({{ code: 409 }} response) box already exists
	/// @fail ({{ code: -1, error: error obj }} response) other error
	///
	/// Attempts to create a box with the given ID

**Example** (synchronous method)

	/// @arg something
	/// Make some things happen
	/// @return {string} - A string


## Types

Types are in curly braces and are separated by pipes. The following are valid types:

* `{number}` - a number
* `{number[]}` - array of ints
* `{number[]|string}` - array of ints or a string
* `{Object|string}` - an object or a string
* `{Cow}` - a cow (where Cow is a class that has been defined)
* `{Cow[]}` - array of cows
* `{Object.<string, number>}` - an object with string keys and number values
* `{{ name: string, age: number }}` - an object with name (which must be a string) and age (which must be a number)
* `{?number}` - a number or undefined
* `{?(number|string)}` - a number or string or undefined

## Building the docs

To create documentation

	cd docs
	npm install
	node build.js [config file]

Config files are of the form docsgen/config.indx.js

If any errors are showing, nodejs might need upgrading -- v0.10.13 works for
me.

If node fails with "Maximum call stack size exceeded", run with a larger stack
size:

	node --stack_size=4096 build.js [config file]

Everything will be built in ./build



## Viewing/hosting the docs

Host ./build in some way. e.g.,

	cd ./build
	python -m SimpleHTTPServer 8080



## Abstracts

An abstract is a JS file which contains just the definitions of classes and
methods. This is useful when you want to document parts of another library
without modifying the library itself.



## Grammars

The comments are parsed using Parsing Expression Grammars (PEG). Explaination
of syntax can be found here: http://pegjs.majda.cz/documentation#grammar-
syntax-and-semantics



## Templates

Mustache templates are used to generate the documentation.
