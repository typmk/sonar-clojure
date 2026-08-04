package au.com.heisenbergtech.sonar;

import org.sonar.api.Plugin;

/**
 * The plugin entry point, in Java rather than Clojure, for one reason.
 *
 * <p>Clojure's runtime resolves {@code clojure/core.clj} through the <em>thread
 * context classloader</em>, not through the classloader that defined the class
 * being initialised. Inside SonarQube's plugin container the context
 * classloader is the web application's, which cannot see this jar, so the
 * first touch of any Clojure-generated class dies in {@code RT.<clinit>} with:
 *
 * <pre>
 *   java.io.FileNotFoundException: Could not locate clojure/core__init.class,
 *   clojure/core.clj or clojure/core.cljc on classpath.
 * </pre>
 *
 * <p>Measured on SonarQube 26.7: the whole server enters a restart loop, since
 * a plugin that throws while being instantiated aborts platform startup.
 *
 * <p>This class cannot be written in Clojure. Loading a {@code gen-class}
 * artifact <em>is</em> the thing that triggers the runtime, so the classloader
 * has to be corrected by something that carries no Clojure static
 * initialiser of its own.
 *
 * <p>The loader is restored in a finally block: leaving it swapped would hand
 * every later extension in the same thread a classloader that is not theirs.
 */
public class ClojurePluginBootstrap implements Plugin {

  private static final String IMPL = "au.com.heisenbergtech.sonar.ClojurePlugin";

  @Override
  public void define(Context context) {
    final Thread thread = Thread.currentThread();
    final ClassLoader previous = thread.getContextClassLoader();
    final ClassLoader ours = ClojurePluginBootstrap.class.getClassLoader();
    try {
      thread.setContextClassLoader(ours);
      Class<?> impl = Class.forName(IMPL, true, ours);
      Plugin delegate = (Plugin) impl.getDeclaredConstructor().newInstance();
      // Every extension namespace is required while this runs, so the whole
      // Clojure side of the plugin is loaded here, under the right loader.
      delegate.define(context);
    } catch (ReflectiveOperationException | LinkageError e) {
      throw new IllegalStateException(
          "sonar-clojure: could not bootstrap the Clojure runtime from " + IMPL
              + ". The plugin jar must contain clojure/core.clj and the context"
              + " classloader must be able to see it.",
          e);
    } finally {
      thread.setContextClassLoader(previous);
    }
  }
}
