module Stratus
end

Dir[File.join(File.dirname(__FILE__), 'stratus/**/*.rb')].sort.each { |lib| require lib }
