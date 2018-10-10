# Harel State Machine

This module is implemented using state machine pattern. However, it is not a flat state machine, but a Harel state machine.

In Harel machine, common properties and behaviors among states are abstracted to a super state, which transforming a flat state space into a hierarchy.

At any time, the object must reside in a leaf-node state, which may be refered as a concrete state. Super state abstraction provides convenience for understanding and implementation, but the object cannot reside in a super state.

# Design Pattern

The context and state are split into different classes, as most state machine patterns do. However, the implementation of `setState` is something tricky for Harel state machine.

A real benefit of Harel machine is that the `enter` and `exit` logic are distributed in the several states along the node path, including the concrete state and its super states.

When transitting from concrete state S1 to S2, S1's exit are executed first, then it's parent state's exit method, until the common ancestor state S of S1 and S2 reached. Since S is the common ancester, there is no need to execute its exit or enter method, as well as all its ancestor's exit or enter method. At this point, the execution walks down the path towards the S2 state. For each states along the path, the enter method is executed.

The code is shown below.

```js
setState (NextState, ...args) {
  let p
  for (p = Object.getPrototypeOf(this);
    !(NextState.prototype instanceof p.constructor);
    p.hasOwnProperty('exit') && p.exit.apply(this),
    p = Object.getPrototypeOf(p));

  this.ctx.state = new NextState(this, ...args)

  let qs = []
  for (let q = NextState.prototype;
    q !== p;
    q.hasOwnProperty('enter') && qs.unshift(q),
    q = Object.getPrototypeOf(q));

  qs.forEach(q => q.enter.apply(this.ctx.state))
}
``` 

The Harel machine hierarchy are encoded using JavaScript class hierarchy. The only way to walk in the hierarchical tree is to retrieve the prototype object of the class constructor and get its prototype through `Object.getPrototypeOf()` method. This is an unusual way in JavaScript but makes sense here.

Also, since the `enter` and `exit` are called by forcefully binding `this` using JavaScript function's `apply` method, the inheritance or overriding feature of these two methods should be avoided.

# Init State

At first thought, the `setState` method is a class method. So it cannot be used to create the first state in context object's constructor.

However, unlike Java or C++, JavaScript is a late-binding language. In `setState`, this is just a previous state. If the previous state is null, we can skip the execution of `exit` methods and create the next state directly. Although it sounds weird to bind a null object to a class method as `this`, it works and conforms to the JavaScript object model perfectly.

In real code, the context object is a mandatory parameter for constructing a state object, so we use it as the faked `this` and apply the `setState` method on it. Then the code can check its type to determine if it's constructing the first state. Meanwhile, passing `null` as `NextState` is also allowed, which means the last state destroyed.

```js
setState (NextState, ...args) {
  let p
  let qs = []

  if (this instanceof State) {
    for (p = Object.getPrototypeOf(this);
      !(NextState.prototype instanceof p.constructor);
      p.hasOwnProperty('exit') && p.exit.apply(this),
      p = Object.getPrototypeOf(p));
  }

  if (NextState) {
    let ctx = this instanceof State ? this.ctx : this
    this.ctx.state = new NextState(ctx, ...args)
    for (let q = NextState.prototype;
      q !== p;
      q.hasOwnProperty('enter') && qs.unshift(q),
      q = Object.getPrototypeOf(q));

    qs.forEach(q => q.enter.apply(this.ctx.state))
  }
}
``` 

Then, in the constructor of context class, the first state can be constructed by:

```js
State.setState.apply(this, ServerHello)
```

This avoids adding a `static` method to init the first state. After all, JavaScript is a dynamic, late-binding language and nothing should be static.


