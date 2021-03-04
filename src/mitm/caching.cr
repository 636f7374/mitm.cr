class Mitm::Caching
  getter capacity : Int32
  getter entries : Hash(String, Tuple(String, String))
  getter mutex : Mutex

  def initialize(@capacity : Int32 = 1024_i32)
    @entries = Hash(String, Tuple(String, String)).new
    @mutex = Mutex.new :unchecked
  end

  def size : Int32
    @mutex.synchronize { @entries.size }
  end

  def clear
    @mutex.synchronize { @entries.clear }
  end

  def get(hostname : String) : Tuple(String, String)?
    @mutex.synchronize { entries[hostname]? }
  end

  def set(hostname : String, entry : Tuple(String, String)) : Bool
    @mutex.synchronize do
      entries.shift if capacity == entries.size
      return false if entries[hostname]?

      entries[hostname] = entry
    end

    true
  end
end
