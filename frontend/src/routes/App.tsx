
import logo from '../images/mutiny-logo.svg';

function App() {
  return (
    <div className="p-8 flex flex-col gap-4">
      <header>
        <img src={logo} className="App-logo" alt="logo" />
      </header>
      <main className='flex flex-col gap-4'>

        <h1>Welcome to Mutiny</h1>
        <h2>You're probably looking for <a href="/tests">the tests</a></h2>

      </main>
    </div>
  );
}

export default App;
