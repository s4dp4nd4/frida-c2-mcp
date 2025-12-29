Java.perform(function() {
  var targetClass = "owasp.sat.agoat.RootDetectionActivity";
  var targetMethod = "isRooted1";
  var targetClassMethod = targetClass + "." + targetMethod;
  console.log(targetClassMethod);
  var hook = Java.use(targetClass);
  var overloadCount = hook[targetMethod].overloads.length;
  console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");
  for (var i = 0; i < overloadCount; i++) {
    hook[targetMethod].overloads[i].implementation = function () {
      console.warn("\n*** entered " + targetClassMethod);
      if (arguments.length) console.log();
      for (var j = 0; j < arguments.length; j++) {
        console.log("arg[" + j + "]: " + arguments[j]);
      }
      var retval = this[targetMethod].apply(this, arguments);
      console.log("\n *** DETECTED INVOCATION ***");
      console.log("\nOriginal retval value: " + retval);
      retval = false;
      console.log("\n*** VALUE MODIFIED ***");
      console.log("\nretval: " + retval);
      console.warn("\n*** exiting " + targetClassMethod);
      return retval;
    }
  }
});